# zero-trust-gateway

[![CI](https://github.com/MahyarNemati/zero-trust-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MahyarNemati/zero-trust-gateway/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/MahyarNemati/zero-trust-gateway)](https://goreportcard.com/report/github.com/MahyarNemati/zero-trust-gateway)

An identity-aware reverse proxy that puts OIDC login and **passkeys** in front
of an application that has no authentication of its own — the BeyondCorp
pattern, in a single static binary.

It handles sessions, per-route access policy with hot reload, step-up
authentication, and mints a short-lived ES256 assertion for the upstream on
every request.

```bash
export ZT_PUBLIC_URL=https://app.example.com
export ZT_UPSTREAM_URL=http://127.0.0.1:3000
export ZT_POLICY_FILE=./policy.yaml
export ZT_SESSION_SECRET=$(openssl rand -base64 32)
export ZT_OIDC_ISSUER=https://id.example.com/realms/main
export ZT_OIDC_CLIENT_ID=zero-trust-gateway

gateway -check     # validate environment and policy
gateway
```

## The security model in two sentences

The **gateway trusts nothing but its own sealed session cookie** — an AEAD
token whose plaintext is only a session id, with the session itself in a store
the browser never sees.

The **upstream trusts nothing but a short-lived assertion** minted by the
gateway and verifiable against a published JWKS. It does not trust headers, it
does not trust network position, and it does not need to know what OIDC is.

```
            ┌──────────────── gateway ────────────────┐
browser ───▶│ policy ─▶ session ─▶ mint assertion ────┼──▶ upstream
            │   │          │                          │
            │   ├─ login ──┴─▶ OIDC (PKCE)            │
            │   └─ step-up ───▶ WebAuthn passkey      │
            └─────────────────────────────────────────┘
                              │
                     GET /.zt/jwks.json  ◀── upstream verifies here
```

## Why an assertion and not a header

The tempting design is `X-Authenticated-User: alice`. It works right up until
anything can reach the upstream other than through the gateway — a port-forward
during an incident, a pod in the same namespace, a misconfigured service — at
which point that header is a complete authentication bypass by `curl`.

So the gateway mints a JWT instead:

- **ES256, signed by a rotating keyring**, published at `/.zt/jwks.json`. The
  upstream verifies a signature, so a forged header is worthless.
- **One-minute TTL by default.** It is minted per request and never needs to
  outlive one, so a captured assertion is useful for about as long as it takes
  to notice.
- **Previous keys are retained for two rotation periods**, so an assertion
  minted seconds before a rotation still verifies. Rotating without an overlap
  window is how you cause a self-inflicted outage at 03:00.

The gateway also **strips any inbound copy** of the assertion header and the
`X-Zt-*` convenience headers before setting its own. Without that, a client
could present its own and the upstream would have no way to tell them apart.
There is a test asserting exactly that (`TestClientSuppliedAssertionHeaderIsStripped`).

The `X-Zt-Subject` / `X-Zt-Email` / `X-Zt-Groups` headers exist for upstreams
that will not verify a JWT. They are a convenience, **not a security
boundary**, and the README says so because someone will otherwise rely on them.

## Policy

YAML, first match wins, with a default of `deny`:

```yaml
default: deny

routes:
  - name: health
    match: { paths: ["/healthz"], methods: ["GET"] }
    allow_anonymous: true

  - name: admin
    match: { paths: ["/admin/*"] }
    require:
      groups_all: ["staff", "platform-admins"]
      email_domains: ["example.com"]
      step_up: true
      step_up_max_age: 10m

  - name: app
    match: { paths: ["/app/*"] }
    require:
      groups_any: ["staff"]
```

See [`policy.example.yaml`](policy.example.yaml), which is validated in CI.

**`default: deny` is the whole point.** With `authenticated`, a route you
forget to list is reachable by anyone who can log in — and you will not find
out from a test, because the route behaves exactly as you expected it to.

Matching supports exact hosts and `*.example.com` wildcards, exact paths and
`/prefix/*` globs, an anchored `path_regex` escape hatch, and methods.
Requirements support `groups_any`, `groups_all`, arbitrary `claims` (scalar
equality or list membership), `email_domains` on a *verified* email, and
step-up.

### Hot reload

The policy file is watched and swapped atomically. **An invalid file is
rejected and the previous policy kept**, so a typo degrades to "your change did
not apply" rather than "the gateway is down" or — far worse — "the gateway now
allows everything".

## Step-up authentication

A route can require a passkey verification *within the last N minutes*, even
though the session is already authenticated:

```yaml
require:
  step_up: true
  step_up_max_age: 10m
```

A request to such a route returns `401` with `X-Zt-Step-Up: required` for API
clients, or an interstitial page that runs the WebAuthn ceremony for browsers.
On success the gateway **rotates the session id** — the privilege level
changed, so the identifier should too — records `step_up_at`, and the assertion
sent upstream carries it.

This is the part most reverse proxies cannot express. "Logged in" and "just
proved they hold the hardware key" are different facts, and destructive
operations deserve the second one.

## Passkeys

WebAuthn via [go-webauthn](https://github.com/go-webauthn/webauthn), with
`ResidentKey: required` and `UserVerification: required`, so credentials are
discoverable (no username needed) and the authenticator must actually verify
the user rather than merely being present.

Both registration and login are supported: a user signs in with OIDC once,
registers a passkey, and afterwards can log in with the passkey alone. The
OIDC profile is synced onto the stored passkey user on every OIDC login, so a
passkey login cannot resurrect stale group membership.

Challenges live in a **sealed, short-lived cookie**, not in the session store.
An unauthenticated passkey login attempt therefore cannot write to the store,
and the cookie is deleted when read, so a challenge cannot be replayed.

## Sessions

- **Sealed cookie.** The cookie is an AEAD token whose plaintext is only the
  session id, with a purpose string bound into the key derivation — so a sealed
  value from one context (login state, WebAuthn challenge) can never be opened
  as another.
- **Absolute and idle lifetimes**, both enforced on load.
- **Rotation on privilege change** (login, step-up) to defeat session fixation.
- **Refresh before expiry.** The IdP refresh token is used a couple of minutes
  before it expires; if the refresh fails, the grant has been revoked and the
  **session is destroyed**. A session must not outlive the authorisation behind
  it.
- **`memory` or `redis`.** Memory is per-process: a restart signs everyone out
  and two replicas do not share sessions. Use Redis for anything real.

### Failing closed

If the session store is unreachable, requests get `503` rather than being
served anonymously. Serving the request would mean serving it *unauthenticated*,
which for a gateway is the one failure mode that must never happen.

## CSRF

State-changing endpoints require **both** a same-origin `Origin`/`Referer`
**and** a session-bound token in `X-CSRF-Token`. Both, because the origin check
alone fails open for clients that send neither header, and the token alone is
unavailable before a session exists. The token is readable at `/.zt/me`.

## Endpoints

Everything the gateway serves lives under the reserved `/.zt/` prefix, and
**requests under it are never proxied** — so an upstream can never be addressed
through a path the gateway also interprets. There is a test for that too.

| Method | Path | |
|---|---|---|
| `GET` | `/.zt/login` | start the OIDC flow (`?rd=` to return somewhere) |
| `GET` | `/.zt/callback` | OIDC redirect URI |
| `POST` | `/.zt/logout` | destroy the session; CSRF required |
| `GET` | `/.zt/me` | current identity and CSRF token |
| `GET` | `/.zt/jwks.json` | public keys for upstreams to verify assertions |
| `POST` | `/.zt/passkey/register/{begin,finish}` | register a passkey |
| `POST` | `/.zt/passkey/login/{begin,finish}` | passwordless login |
| `POST` | `/.zt/passkey/stepup/{begin,finish}` | step-up verification |
| `GET` | `/.zt/healthz` `/.zt/readyz` | liveness, readiness |

Metrics are on a **separate listener** (`ZT_METRICS_ADDR`, default `:9090`) so
`/metrics` is never reachable through the public port that fronts your
application.

## Configuration

Entirely by environment variable; see [`.env.example`](.env.example) for every
variable with notes. Validation happens at startup and reports *all* problems
at once, so you fix one list rather than restarting six times.

Required: `ZT_PUBLIC_URL`, `ZT_UPSTREAM_URL`, `ZT_POLICY_FILE`,
`ZT_SESSION_SECRET`, `ZT_OIDC_ISSUER`, `ZT_OIDC_CLIENT_ID`.

## Layout

```
cmd/gateway/          wiring, lifecycle, graceful shutdown
internal/
  gateway/            composition: policy -> auth -> proxy, and the HTTP surface
  policy/             YAML engine + atomic hot-reload watcher
  session/            sealed cookies, manager, memory and Redis stores
  oidcauth/           authorization code flow with PKCE, nonce, refresh
  passkey/            WebAuthn registration, discoverable login, step-up
  token/              ES256 assertions, rotating keyring, JWKS handler
  audit/              structured JSON audit log
  metrics/            Prometheus instruments
  httpx/              request ids, security headers, safe redirect, constant-time compare
  testutil/mockidp/         a real OIDC provider for tests
  testutil/authenticator/   a virtual WebAuthn authenticator for tests
```

## Testing

```bash
make test        # unit + integration
make test-race   # with the race detector (needs working cgo)
make check       # validate environment and policy
```

The thing worth copying here is `internal/testutil`. There is a **real mock
IdP** (discovery, JWKS, authorize, token, refresh, revocation, with an actual
RSA key) and a **virtual WebAuthn authenticator** that produces genuine
attestations and assertions.

That means the integration tests drive the *real* ceremonies end to end — OIDC
code exchange, passkey registration, step-up, session rotation — rather than
stubbing them at a trait boundary. Mocking out the crypto in an authentication
proxy would leave the only interesting part untested.

The suite covers, among others: anonymous routes proxying without an assertion,
forged assertion headers being stripped, insufficient groups returning 403,
step-up gating admin and being satisfied by a passkey, CSRF and cross-origin
rejection, and the reserved prefix never reaching the upstream.

CI additionally runs the session and passkey stores against a **real Redis**
(the tests use miniredis by default, which is its own implementation),
`govulncheck`, and a Docker build that validates the example policy inside the
image.

## Limitations

- **Single upstream.** One `ZT_UPSTREAM_URL`; routing to several backends is
  the job of whatever sits behind this.
- **No TLS termination.** Run behind a terminator. `ZT_PUBLIC_URL` must still
  be the external `https://` URL, since cookie flags, the WebAuthn origin and
  the OIDC redirect URI are all derived from it.
- **Passkey users live in the session store's backend.** With
  `ZT_SESSION_STORE=memory`, registered passkeys are lost on restart.
- **No admin UI** for revoking individual credentials or sessions.
- **Policy is per-request, not per-response.** The gateway cannot filter or
  redact what the upstream returns.
- **No mTLS to the upstream**, so the upstream must verify the assertion rather
  than trusting the connection.

## License

MIT — see [LICENSE](LICENSE).
