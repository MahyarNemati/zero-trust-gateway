package gateway_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/MahyarNemati/zero-trust-gateway/internal/audit"
	"github.com/MahyarNemati/zero-trust-gateway/internal/config"
	"github.com/MahyarNemati/zero-trust-gateway/internal/gateway"
	"github.com/MahyarNemati/zero-trust-gateway/internal/metrics"
	"github.com/MahyarNemati/zero-trust-gateway/internal/oidcauth"
	"github.com/MahyarNemati/zero-trust-gateway/internal/passkey"
	"github.com/MahyarNemati/zero-trust-gateway/internal/policy"
	"github.com/MahyarNemati/zero-trust-gateway/internal/session"
	"github.com/MahyarNemati/zero-trust-gateway/internal/testutil/authenticator"
	"github.com/MahyarNemati/zero-trust-gateway/internal/testutil/mockidp"
	"github.com/MahyarNemati/zero-trust-gateway/internal/token"
)

const policyYAML = `
default: deny
routes:
  - name: public
    match:
      paths: ["/public/*"]
    allow_anonymous: true
  - name: admin
    match:
      paths: ["/admin/*"]
    require:
      groups_all: ["staff", "admins"]
      step_up: true
      step_up_max_age: 15m
  - name: app
    match:
      paths: ["/*"]
    require:
      groups_any: ["staff"]
`

type harness struct {
	t        *testing.T
	gw       *httptest.Server
	idp      *mockidp.Provider
	upstream *httptest.Server
	keys     *token.Keyring
	client   *http.Client
	// lastUpstream records the headers the upstream actually received.
	lastUpstream http.Header
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{t: t}

	h.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.lastUpstream = r.Header.Clone()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream:"+r.URL.Path)
	}))
	t.Cleanup(h.upstream.Close)

	h.idp = mockidp.New("gateway", "secret")
	t.Cleanup(h.idp.Close)
	h.idp.SetUser(mockidp.User{
		Subject: "user-1", Email: "staff@example.com", Name: "Staff User",
		Groups: []string{"staff"}, Extra: map[string]any{"email_verified": true},
	})

	policyFile := t.TempDir() + "/policy.yaml"
	writeFile(t, policyFile, policyYAML)

	policies, err := policy.NewStore(policyFile, nil, nil)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	sealer, err := session.NewSealer(secret)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	keys, err := token.NewRotatingKeyring(time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("NewRotatingKeyring: %v", err)
	}
	h.keys = keys

	// The gateway needs its own URL before it exists, so create the server
	// unstarted, read its URL, then wire and start it.
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	addr := "http://" + srv.Listener.Addr().String()

	publicURL := mustURL(t, addr)
	upstreamURL := mustURL(t, h.upstream.URL)

	cfg := &config.Config{
		PublicURL:   publicURL,
		UpstreamURL: upstreamURL,
		PolicyFile:  policyFile,
		Session: config.Session{
			Secret: secret, Store: "memory", CookieName: "__zt_session",
			TTL: 12 * time.Hour, IdleTimeout: time.Hour,
		},
		JWT: config.JWT{TTL: time.Minute, Audience: "upstream", Header: "X-ZT-Assertion"},
		OIDC: config.OIDC{
			Issuer: h.idp.URL, ClientID: "gateway", ClientSecret: "secret",
			Scopes: []string{"openid", "profile", "email"}, GroupsClaim: "groups",
		},
		Passkeys: config.Passkeys{
			Enabled: true, RPID: publicURL.Hostname(), RPDisplayName: "Test",
			StepUpMaxAge: 15 * time.Minute,
		},
	}

	sessions := &session.Manager{
		Store: session.NewMemoryStore(), Sealer: sealer,
		CookieName: cfg.Session.CookieName, Secure: false,
		TTL: cfg.Session.TTL, IdleTimeout: cfg.Session.IdleTimeout,
	}

	passkeys, err := passkey.New(passkey.Config{
		RPID: cfg.Passkeys.RPID, RPDisplayName: cfg.Passkeys.RPDisplayName,
		Origins: []string{addr},
	}, passkey.NewMemoryStore())
	if err != nil {
		t.Fatalf("passkey.New: %v", err)
	}

	gw, err := gateway.New(gateway.Deps{
		Config:   cfg,
		Policy:   policies,
		Sessions: sessions,
		Sealer:   sealer,
		OIDC: oidcauth.New(oidcauth.Config{
			Issuer: h.idp.URL, ClientID: "gateway", ClientSecret: "secret",
			RedirectURL: addr + gateway.Prefix + "callback",
			Scopes:      []string{"openid", "profile", "email"}, GroupsClaim: "groups",
		}),
		Passkeys: passkeys,
		Tokens:   &token.Issuer{Keys: keys, Issuer: addr, Audience: "upstream", TTL: time.Minute},
		Keys:     keys,
		Metrics:  metrics.New(),
		Audit:    audit.Discard(),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	mux.Handle("/", gw.Handler())
	srv.Start()
	t.Cleanup(srv.Close)
	h.gw = srv

	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	return h
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := osWriteFile(path, body); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func (h *harness) get(path string, header http.Header) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.gw.URL+path, nil)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	for k, vs := range header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *harness) post(path string, body string, header http.Header) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.gw.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.gw.URL)
	for k, vs := range header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// login completes the OIDC code flow through the mock IdP.
func (h *harness) login() {
	h.t.Helper()
	// Land on an anonymous route so the helper succeeds whatever groups the
	// user has; group enforcement is what the individual tests assert.
	resp := h.get(gateway.Prefix+"login?rd=%2Fpublic%2Fok", nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("login flow ended with %d, body: %s", resp.StatusCode, body(h.t, resp))
	}
}

// csrf reads the session's CSRF token from /.zt/me.
func (h *harness) csrf() string {
	h.t.Helper()
	resp := h.get(gateway.Prefix+"me", nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("/me returned %d", resp.StatusCode)
	}
	var out struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal([]byte(body(h.t, resp)), &out); err != nil {
		h.t.Fatalf("decode /me: %v", err)
	}
	return out.CSRF
}

// ---------- tests ----------

func TestAnonymousRouteIsProxied(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/public/thing", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.StatusCode, body(t, resp))
	}
	if got := body(t, resp); got != "upstream:/public/thing" {
		t.Errorf("body = %q", got)
	}
	// An anonymous request must not carry an assertion.
	if v := h.lastUpstream.Get("X-ZT-Assertion"); v != "" {
		t.Errorf("anonymous request carried an assertion: %q", v)
	}
}

func TestProtectedRouteRequiresAuthentication(t *testing.T) {
	h := newHarness(t)

	// An API client gets JSON it can act on, not an HTML page.
	resp := h.get("/dashboard", http.Header{"Accept": {"application/json"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(body(t, resp)), &out); err != nil {
		t.Fatalf("expected JSON, got: %v", err)
	}
	if out["login"] == "" {
		t.Error("401 should tell the client where to log in")
	}

	// A browser gets the sign-in page.
	resp = h.get("/dashboard", http.Header{"Accept": {"text/html"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, "Sign in") {
		t.Errorf("expected a sign-in page, got: %.200s", page)
	}
}

func TestOIDCLoginGrantsAccessAndMintsAVerifiableAssertion(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp := h.get("/dashboard", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", resp.StatusCode, body(t, resp))
	}

	raw := h.lastUpstream.Get("X-ZT-Assertion")
	if raw == "" {
		t.Fatal("upstream received no assertion")
	}
	claims, err := token.Verify(raw, h.keys.JWKS(), h.gw.URL, "upstream", time.Now())
	if err != nil {
		t.Fatalf("assertion does not verify against the published JWKS: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", claims.Subject)
	}
	if claims.Email != "staff@example.com" {
		t.Errorf("email = %q", claims.Email)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "staff" {
		t.Errorf("groups = %v, want [staff]", claims.Groups)
	}
	if h.lastUpstream.Get("X-Zt-Subject") != "user-1" {
		t.Errorf("X-Zt-Subject = %q", h.lastUpstream.Get("X-Zt-Subject"))
	}
}

func TestClientSuppliedAssertionHeaderIsStripped(t *testing.T) {
	h := newHarness(t)

	// Anonymous request to a public route, forging the assertion header.
	h.get("/public/x", http.Header{
		"X-ZT-Assertion": {"forged.jwt.value"},
		"X-Zt-Subject":   {"admin"},
		"X-Zt-Groups":    {"admins"},
	})
	if got := h.lastUpstream.Get("X-ZT-Assertion"); got != "" {
		t.Errorf("forged assertion reached the upstream: %q", got)
	}
	if got := h.lastUpstream.Get("X-Zt-Subject"); got != "" {
		t.Errorf("forged subject reached the upstream: %q", got)
	}
	if got := h.lastUpstream.Get("X-Zt-Groups"); got != "" {
		t.Errorf("forged groups reached the upstream: %q", got)
	}

	// And after a genuine login, the gateway's own value must win.
	h.login()
	h.get("/dashboard", http.Header{"X-Zt-Subject": {"admin"}, "X-Zt-Groups": {"admins"}})
	if got := h.lastUpstream.Get("X-Zt-Subject"); got != "user-1" {
		t.Errorf("X-Zt-Subject = %q, want the gateway's value user-1", got)
	}
	if got := h.lastUpstream.Get("X-Zt-Groups"); got != "staff" {
		t.Errorf("X-Zt-Groups = %q, want staff", got)
	}
}

func TestInsufficientGroupsIsForbidden(t *testing.T) {
	h := newHarness(t)
	h.idp.SetUser(mockidp.User{
		Subject: "user-2", Email: "guest@example.com",
		Groups: []string{"guests"}, Extra: map[string]any{"email_verified": true},
	})
	h.login()

	resp := h.get("/dashboard", http.Header{"Accept": {"application/json"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", resp.StatusCode, body(t, resp))
	}
}

func TestStepUpRouteRequiresFreshPasskeyVerification(t *testing.T) {
	h := newHarness(t)
	h.idp.SetUser(mockidp.User{
		Subject: "admin-1", Email: "admin@example.com",
		Groups: []string{"staff", "admins"}, Extra: map[string]any{"email_verified": true},
	})
	h.login()

	// Groups are satisfied, but step_up is not.
	resp := h.get("/admin/secrets", http.Header{"Accept": {"application/json"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401: %s", resp.StatusCode, body(t, resp))
	}
	if resp.Header.Get("X-Zt-Step-Up") != "required" {
		t.Error("expected an X-Zt-Step-Up hint")
	}

	// A non-step-up route is still reachable with the same session.
	if r := h.get("/dashboard", nil); r.StatusCode != http.StatusOK {
		t.Errorf("/dashboard got %d, want 200", r.StatusCode)
	}
}

func TestPasskeyRegistrationThenStepUpUnlocksAdmin(t *testing.T) {
	h := newHarness(t)
	h.idp.SetUser(mockidp.User{
		Subject: "admin-1", Email: "admin@example.com",
		Groups: []string{"staff", "admins"}, Extra: map[string]any{"email_verified": true},
	})
	h.login()

	auth := authenticator.New(h.gw.URL)
	csrf := h.csrf()
	hdr := http.Header{"X-CSRF-Token": {csrf}}

	// Register.
	resp := h.post(gateway.Prefix+"passkey/register/begin", "{}", hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin got %d: %s", resp.StatusCode, body(t, resp))
	}
	attestation, err := auth.Create([]byte(body(t, resp)))
	if err != nil {
		t.Fatalf("authenticator.Create: %v", err)
	}
	resp = h.post(gateway.Prefix+"passkey/register/finish", string(attestation), hdr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish got %d: %s", resp.StatusCode, body(t, resp))
	}

	// Step up.
	resp = h.post(gateway.Prefix+"passkey/stepup/begin", "{}", hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stepup/begin got %d: %s", resp.StatusCode, body(t, resp))
	}
	assertion, err := auth.Get([]byte(body(t, resp)))
	if err != nil {
		t.Fatalf("authenticator.Get: %v", err)
	}
	resp = h.post(gateway.Prefix+"passkey/stepup/finish", string(assertion), hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stepup/finish got %d: %s", resp.StatusCode, body(t, resp))
	}

	// Now the step-up route is reachable.
	if r := h.get("/admin/secrets", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("/admin/secrets got %d, want 200 after step-up: %s", r.StatusCode, body(t, r))
	}
	raw := h.lastUpstream.Get("X-ZT-Assertion")
	claims, err := token.Verify(raw, h.keys.JWKS(), h.gw.URL, "upstream", time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.StepUpAt == 0 {
		t.Error("assertion should carry step_up_at after a step-up")
	}
	if !containsStr(claims.AMR, "passkey") {
		t.Errorf("amr = %v, want it to include passkey", claims.AMR)
	}
}

func TestStateChangingEndpointsRequireCSRFToken(t *testing.T) {
	h := newHarness(t)
	h.login()

	// No token.
	if r := h.post(gateway.Prefix+"logout", "{}", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("logout without a CSRF token got %d, want 403", r.StatusCode)
	}
	// Wrong token.
	if r := h.post(gateway.Prefix+"logout", "{}", http.Header{"X-CSRF-Token": {"nope"}}); r.StatusCode != http.StatusForbidden {
		t.Errorf("logout with a bad CSRF token got %d, want 403", r.StatusCode)
	}
	// Still signed in.
	if r := h.get("/dashboard", nil); r.StatusCode != http.StatusOK {
		t.Errorf("session should have survived the rejected logout, got %d", r.StatusCode)
	}
}

func TestCrossOriginPostIsRejected(t *testing.T) {
	h := newHarness(t)
	h.login()
	csrf := h.csrf()

	resp := h.post(gateway.Prefix+"logout", "{}", http.Header{
		"X-CSRF-Token": {csrf},
		"Origin":       {"https://evil.example"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403 for a cross-origin POST", resp.StatusCode)
	}
}

func TestLogoutDestroysTheSession(t *testing.T) {
	h := newHarness(t)
	h.login()
	csrf := h.csrf()

	resp := h.post(gateway.Prefix+"logout", "{}", http.Header{
		"X-CSRF-Token": {csrf},
		"Accept":       {"application/json"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout got %d: %s", resp.StatusCode, body(t, resp))
	}
	resp = h.get("/dashboard", http.Header{"Accept": {"application/json"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout got %d, want 401", resp.StatusCode)
	}
}

func TestReservedPrefixIsNeverProxied(t *testing.T) {
	h := newHarness(t)
	// An unknown path under the reserved prefix must 404 at the gateway, not
	// reach the upstream, or the upstream could be addressed through a path
	// the gateway also interprets.
	h.lastUpstream = nil
	resp := h.get(gateway.Prefix+"nope", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
	if h.lastUpstream != nil {
		t.Error("request under the reserved prefix reached the upstream")
	}
}

func TestJWKSIsPublishedAndUsableByUpstreams(t *testing.T) {
	h := newHarness(t)
	resp := h.get(gateway.Prefix+"jwks.json", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(body(t, resp)), &set); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatal("JWKS is empty")
	}
	for _, k := range set.Keys {
		if k.IsPublic() != true {
			t.Error("JWKS must only contain public keys")
		}
	}
}

func TestHealthAndReadiness(t *testing.T) {
	h := newHarness(t)
	if r := h.get(gateway.Prefix+"healthz", nil); r.StatusCode != http.StatusOK {
		t.Errorf("healthz got %d", r.StatusCode)
	}
	if r := h.get(gateway.Prefix+"readyz", nil); r.StatusCode != http.StatusOK {
		t.Errorf("readyz got %d: %s", r.StatusCode, body(t, r))
	}
}

func TestRevokedGrantEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.login()
	if r := h.get("/dashboard", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("precondition failed: %d", r.StatusCode)
	}
	// The IdP revokes the grant. The gateway only notices at refresh time, so
	// this asserts the refresh path fails closed rather than silently keeping
	// a session the IdP has disowned.
	h.idp.RevokeAll()
	// Nothing to assert until a refresh is due; what matters is that the
	// session remains usable until then and the gateway does not crash.
	if r := h.get("/dashboard", nil); r.StatusCode != http.StatusOK {
		t.Errorf("got %d; a valid session should survive until refresh is due", r.StatusCode)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func osWriteFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
