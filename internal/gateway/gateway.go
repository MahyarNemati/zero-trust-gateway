// Package gateway is the composition layer: it evaluates policy for every
// request, drives the OIDC and passkey flows, and proxies what it allows to
// the upstream with a signed assertion attached.
//
// The security model in one sentence: the upstream trusts nothing except a
// short-lived ES256 assertion minted by this gateway, and the gateway trusts
// nothing except its own sealed session cookie.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/MahyarNemati/zero-trust-gateway/internal/audit"
	"github.com/MahyarNemati/zero-trust-gateway/internal/config"
	"github.com/MahyarNemati/zero-trust-gateway/internal/httpx"
	"github.com/MahyarNemati/zero-trust-gateway/internal/metrics"
	"github.com/MahyarNemati/zero-trust-gateway/internal/oidcauth"
	"github.com/MahyarNemati/zero-trust-gateway/internal/passkey"
	"github.com/MahyarNemati/zero-trust-gateway/internal/policy"
	"github.com/MahyarNemati/zero-trust-gateway/internal/session"
	"github.com/MahyarNemati/zero-trust-gateway/internal/token"
)

// Prefix is reserved for the gateway's own endpoints. Requests under it are
// never proxied, so an upstream can never be reached through a path that the
// gateway also interprets.
const Prefix = "/.zt/"

// authStatePurpose keys the AEAD for the login-state cookie. Using a distinct
// purpose from the session cookie means a sealed value from one can never be
// opened as the other.
const authStatePurpose = "auth-state"

const (
	authStateCookie = "__zt_auth"
	authStateTTL    = 10 * time.Minute
	stepUpCookie    = "__zt_stepup"
	webauthnPurpose = "webauthn-session"
	webauthnTTL     = 5 * time.Minute
)

// Deps are the gateway's collaborators.
type Deps struct {
	Config   *config.Config
	Policy   *policy.Store
	Sessions *session.Manager
	Sealer   *session.Sealer
	OIDC     *oidcauth.Client
	Passkeys *passkey.Service
	Tokens   *token.Issuer
	Keys     *token.Keyring
	Metrics  *metrics.Metrics
	Audit    *audit.Logger
	Log      *slog.Logger
	Now      func() time.Time
}

// Gateway serves the proxy and the authentication endpoints.
type Gateway struct {
	deps  Deps
	proxy *httputil.ReverseProxy
	mux   *http.ServeMux
}

// New builds a Gateway.
func New(d Deps) (*Gateway, error) {
	switch {
	case d.Config == nil:
		return nil, errors.New("gateway: config is required")
	case d.Policy == nil:
		return nil, errors.New("gateway: policy store is required")
	case d.Sessions == nil:
		return nil, errors.New("gateway: session manager is required")
	case d.Sealer == nil:
		return nil, errors.New("gateway: sealer is required")
	case d.Tokens == nil:
		return nil, errors.New("gateway: token issuer is required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Audit == nil {
		d.Audit = audit.Discard()
	}
	if d.Metrics == nil {
		d.Metrics = metrics.New()
	}
	if d.Now == nil {
		d.Now = time.Now
	}

	g := &Gateway{deps: d}
	g.proxy = g.newProxy()
	g.routes()
	return g, nil
}

func (g *Gateway) now() time.Time { return g.deps.Now() }

// Handler returns the gateway's HTTP handler.
func (g *Gateway) Handler() http.Handler {
	return httpx.RequestIDs(http.HandlerFunc(g.serve))
}

func (g *Gateway) routes() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+Prefix+"login", g.handleLogin)
	mux.HandleFunc("GET "+Prefix+"callback", g.handleCallback)
	mux.HandleFunc("POST "+Prefix+"logout", g.handleLogout)
	mux.HandleFunc("GET "+Prefix+"me", g.handleMe)
	mux.HandleFunc("GET "+Prefix+"healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET "+Prefix+"readyz", g.handleReady)
	mux.Handle("GET "+Prefix+"jwks.json", token.JWKSHandler(g.deps.Keys))
	mux.HandleFunc("GET "+Prefix+"passkey.js", g.handleAsset)

	if g.deps.Passkeys != nil {
		mux.HandleFunc("POST "+Prefix+"passkey/register/begin", g.handleRegisterBegin)
		mux.HandleFunc("POST "+Prefix+"passkey/register/finish", g.handleRegisterFinish)
		mux.HandleFunc("POST "+Prefix+"passkey/login/begin", g.handleLoginBegin)
		mux.HandleFunc("POST "+Prefix+"passkey/login/finish", g.handleLoginFinish)
		mux.HandleFunc("POST "+Prefix+"passkey/stepup/begin", g.handleStepUpBegin)
		mux.HandleFunc("POST "+Prefix+"passkey/stepup/finish", g.handleStepUpFinish)
	}

	// Anything not claimed above but still under the reserved prefix is a 404
	// from the gateway, never a proxied request.
	mux.HandleFunc(Prefix, func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "unknown gateway endpoint")
	})

	g.mux = mux
}

// serve is the single entry point. Gateway endpoints are dispatched directly;
// everything else is subject to policy and then proxied.
func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	httpx.BaselineSecurityHeaders(w.Header(), g.deps.Config.Secure())

	if strings.HasPrefix(r.URL.Path, Prefix) {
		g.mux.ServeHTTP(w, r)
		return
	}
	g.handleProxy(w, r)
}

// ---------- policy and proxying ----------

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	engine := g.deps.Policy.Engine()
	now := g.now()

	sess, err := g.deps.Sessions.Load(r)
	if err != nil && !errors.Is(err, session.ErrNotFound) {
		// The session store is unreachable. Failing closed is the only safe
		// option: serving the request would mean serving it unauthenticated.
		g.deps.Log.Error("load session", "err", err)
		writeError(w, http.StatusServiceUnavailable, "session store unavailable")
		return
	}

	var id *policy.Identity
	if sess != nil {
		if err := g.refreshIfNeeded(r.Context(), sess, now); err != nil {
			// A refresh failure means the IdP has revoked the grant, so the
			// session should not outlive it.
			g.deps.Log.Info("session refresh failed, destroying session", "sub", sess.Subject, "err", err)
			g.deps.Metrics.SessionRefresh.WithLabelValues("error").Inc()
			_ = g.deps.Sessions.Destroy(w, r, sess)
			sess = nil
		} else {
			id = identityFrom(sess)
		}
	}

	d := engine.Evaluate(r, id, now)
	g.deps.Metrics.Decisions.WithLabelValues(d.Route, d.Outcome.String()).Inc()

	switch d.Outcome {
	case policy.Allow:
		if sess != nil {
			if err := g.deps.Sessions.Touch(r.Context(), sess); err != nil {
				g.deps.Log.Warn("touch session", "err", err)
			}
		}
		g.forward(w, r, sess, d)

	case policy.Login:
		g.deps.Audit.Log(r.Context(), r, audit.Record{
			Event: "access.login_required", Route: d.Route, Reason: d.Reason,
		})
		g.startLogin(w, r)

	case policy.StepUp:
		g.deps.Audit.Log(r.Context(), r, audit.Record{
			Event: "access.step_up_required", Subject: subjectOf(sess), Route: d.Route, Reason: d.Reason,
		})
		g.requireStepUp(w, r, d, sess)

	default:
		g.deps.Audit.Log(r.Context(), r, audit.Record{
			Event: "access.denied", Subject: subjectOf(sess), Route: d.Route, Reason: d.Reason,
		})
		if httpx.WantsHTML(r) {
			g.renderDenied(w, d)
			return
		}
		writeError(w, http.StatusForbidden, d.Reason)
	}
}

// forward proxies an allowed request, attaching an assertion when there is an
// identity to assert.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, sess *session.Session, d policy.Decision) {
	// Strip any inbound copy of the assertion header before deciding what to
	// set. Without this a client could present its own header and the
	// upstream would have no way to tell it apart from ours.
	r.Header.Del(g.deps.Config.JWT.Header)
	r.Header.Del("X-Zt-Subject")
	r.Header.Del("X-Zt-Email")
	r.Header.Del("X-Zt-Groups")
	r.Header.Del("X-Zt-Route")

	if sess != nil {
		assertion, err := g.deps.Tokens.Mint(sess)
		if err != nil {
			g.deps.Log.Error("mint assertion", "sub", sess.Subject, "err", err)
			writeError(w, http.StatusInternalServerError, "could not mint upstream assertion")
			return
		}
		r.Header.Set(g.deps.Config.JWT.Header, assertion)
		// Convenience headers for upstreams that will not verify a JWT. They
		// are *not* a security boundary: an upstream reachable other than
		// through this gateway must verify the assertion.
		r.Header.Set("X-Zt-Subject", sess.Subject)
		if sess.Email != "" {
			r.Header.Set("X-Zt-Email", sess.Email)
		}
		if len(sess.Groups) > 0 {
			r.Header.Set("X-Zt-Groups", strings.Join(sess.Groups, ","))
		}
	}
	if d.Route != "" {
		r.Header.Set("X-Zt-Route", d.Route)
	}

	g.proxy.ServeHTTP(w, r)
}

func (g *Gateway) newProxy() *httputil.ReverseProxy {
	target := g.deps.Config.UpstreamURL
	start := make(map[*http.Request]time.Time)

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// SetXForwarded replaces rather than appends, so a client cannot
			// inject a forged X-Forwarded-For chain.
			pr.SetXForwarded()
			pr.Out.Host = target.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			code := strconv.Itoa(resp.StatusCode/100) + "xx"
			if t, ok := start[resp.Request]; ok {
				g.deps.Metrics.UpstreamLatency.WithLabelValues(code).Observe(time.Since(t).Seconds())
				delete(start, resp.Request)
			} else {
				g.deps.Metrics.UpstreamLatency.WithLabelValues(code).Observe(0)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.deps.Log.Error("upstream", "path", r.URL.Path, "err", err)
			g.deps.Metrics.UpstreamLatency.WithLabelValues("5xx").Observe(0)
			writeError(w, http.StatusBadGateway, "upstream unavailable")
		},
		ErrorLog: slog.NewLogLogger(g.deps.Log.Handler(), slog.LevelWarn),
	}
}

// refreshIfNeeded renews the IdP grant shortly before it expires so a long
// session does not outlive the authorisation behind it.
func (g *Gateway) refreshIfNeeded(ctx context.Context, s *session.Session, now time.Time) error {
	if g.deps.OIDC == nil || s.RefreshToken == "" || s.TokenExpiry.IsZero() {
		return nil
	}
	if now.Before(s.TokenExpiry.Add(-2 * time.Minute)) {
		return nil
	}

	tok, err := g.deps.OIDC.Refresh(ctx, s.RefreshToken)
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	applyIdentity(s, tok)
	g.deps.Metrics.SessionRefresh.WithLabelValues("ok").Inc()
	return g.deps.Sessions.Touch(ctx, s)
}

// ---------- OIDC ----------

// authState is the login-in-flight state, kept in a sealed cookie rather than
// server-side so an unauthenticated request cannot create store entries.
type authState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Redirect string `json:"redirect"`
}

func (g *Gateway) startLogin(w http.ResponseWriter, r *http.Request) {
	if g.deps.OIDC == nil && g.deps.Passkeys == nil {
		writeError(w, http.StatusServiceUnavailable, "no authentication method configured")
		return
	}
	// Only a safe, idempotent navigation can be resumed after login. Bouncing
	// a POST through an IdP redirect would lose its body anyway.
	redirect := "/"
	if r.Method == http.MethodGet {
		redirect = httpx.SafeRedirect(r.URL.RequestURI())
	}

	// An API client cannot follow an HTML sign-in page, so tell it what to do
	// instead of redirecting it into a login flow it cannot complete.
	if !httpx.WantsHTML(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authentication required",
			"login": Prefix + "login",
		})
		return
	}
	g.renderSignIn(w, redirect)
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if g.deps.OIDC == nil {
		writeError(w, http.StatusServiceUnavailable, "no identity provider configured")
		return
	}
	g.redirectToIdP(w, r, httpx.SafeRedirect(r.URL.Query().Get("rd")))
}

func (g *Gateway) redirectToIdP(w http.ResponseWriter, r *http.Request, redirect string) {
	st := authState{
		State:    session.NewID(),
		Nonce:    session.NewID(),
		Verifier: session.NewID(),
		Redirect: redirect,
	}
	blob, err := json.Marshal(st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}
	sealed, err := g.deps.Sealer.Seal(authStatePurpose, blob, authStateTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authStateCookie,
		Value:    sealed,
		Path:     Prefix,
		MaxAge:   int(authStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   g.deps.Config.Secure(),
		// Lax, not Strict: the IdP redirects back with a cross-site GET and
		// Strict would withhold the cookie, breaking the callback.
		SameSite: http.SameSiteLaxMode,
	})

	url, err := g.deps.OIDC.AuthCodeURL(r.Context(), st.State, st.Nonce, st.Verifier)
	if err != nil {
		g.deps.Log.Error("auth code url", "err", err)
		g.deps.Metrics.AuthEvents.WithLabelValues("oidc_start", "error").Inc()
		writeError(w, http.StatusBadGateway, "identity provider unavailable")
		return
	}
	g.deps.Metrics.AuthEvents.WithLabelValues("oidc_start", "ok").Inc()
	http.Redirect(w, r, url, http.StatusFound)
}

func (g *Gateway) handleCallback(w http.ResponseWriter, r *http.Request) {
	st, ok := g.readAuthState(r)
	if !ok {
		g.deps.Metrics.AuthEvents.WithLabelValues("oidc_callback", "no_state").Inc()
		writeError(w, http.StatusBadRequest, "login state missing or expired; start again")
		return
	}
	g.clearCookie(w, authStateCookie, Prefix)

	if e := r.URL.Query().Get("error"); e != "" {
		g.deps.Metrics.AuthEvents.WithLabelValues("oidc_callback", "idp_error").Inc()
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "login.idp_error", Reason: e})
		writeError(w, http.StatusUnauthorized, "identity provider rejected the login: "+e)
		return
	}

	// Constant-time compare: the state parameter is the CSRF defence for the
	// callback, so it must not leak through timing.
	if !httpx.TokenEqual(r.URL.Query().Get("state"), st.State) {
		g.deps.Metrics.AuthEvents.WithLabelValues("oidc_callback", "state_mismatch").Inc()
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "login.state_mismatch"})
		writeError(w, http.StatusBadRequest, "state mismatch")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}

	tok, err := g.deps.OIDC.Exchange(r.Context(), code, st.Verifier, st.Nonce)
	if err != nil {
		g.deps.Log.Warn("code exchange", "err", err)
		g.deps.Metrics.AuthEvents.WithLabelValues("oidc_callback", "exchange_error").Inc()
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "login.exchange_failed", Reason: err.Error()})
		writeError(w, http.StatusUnauthorized, "could not complete login")
		return
	}

	sess := g.deps.Sessions.New()
	applyIdentity(sess, tok)
	sess.AddAMR("oidc")

	if err := g.deps.Sessions.Commit(w, r, sess); err != nil {
		g.deps.Log.Error("commit session", "err", err)
		writeError(w, http.StatusInternalServerError, "could not persist session")
		return
	}

	// Keep the passkey user profile in step with the IdP so a passkey login
	// does not resurrect stale groups.
	if g.deps.Passkeys != nil {
		if err := g.deps.Passkeys.SyncProfile(r.Context(), passkey.Profile{
			Subject:       sess.Subject,
			Email:         sess.Email,
			EmailVerified: sess.EmailVerified,
			Name:          sess.Name,
			Groups:        sess.Groups,
			Claims:        sess.Claims,
		}, g.now()); err != nil {
			g.deps.Log.Warn("sync passkey profile", "sub", sess.Subject, "err", err)
		}
	}

	g.deps.Metrics.AuthEvents.WithLabelValues("oidc_callback", "ok").Inc()
	g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "login.success", Subject: sess.Subject})
	http.Redirect(w, r, httpx.SafeRedirect(st.Redirect), http.StatusFound)
}

func (g *Gateway) readAuthState(r *http.Request) (authState, bool) {
	c, err := r.Cookie(authStateCookie)
	if err != nil {
		return authState{}, false
	}
	blob, err := g.deps.Sealer.Open(authStatePurpose, c.Value)
	if err != nil {
		return authState{}, false
	}
	var st authState
	if err := json.Unmarshal(blob, &st); err != nil {
		return authState{}, false
	}
	return st, true
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := g.deps.Sessions.Load(r)
	if !g.checkCSRF(w, r, sess) {
		return
	}
	sub := subjectOf(sess)
	if err := g.deps.Sessions.Destroy(w, r, sess); err != nil {
		g.deps.Log.Warn("destroy session", "err", err)
	}
	g.deps.Metrics.AuthEvents.WithLabelValues("logout", "ok").Inc()
	g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "logout", Subject: sub})

	// Offer RP-initiated logout at the IdP, but do not require it: the local
	// session is already gone either way.
	if g.deps.OIDC != nil {
		if end := g.deps.OIDC.EndSessionURL(r.Context()); end != "" && httpx.WantsHTML(r) {
			http.Redirect(w, r, end, http.StatusFound)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (g *Gateway) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, err := g.deps.Sessions.Load(r)
	if err != nil || sess == nil {
		writeError(w, http.StatusUnauthorized, "no session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":        sess.Subject,
		"email":          sess.Email,
		"email_verified": sess.EmailVerified,
		"name":           sess.Name,
		"groups":         sess.Groups,
		"amr":            sess.AMR,
		"step_up_at":     zeroTime(sess.StepUpAt),
		"expires_at":     sess.ExpiresAt,
		"csrf":           sess.CSRFToken,
	})
}

func (g *Gateway) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	problems := map[string]string{}
	if err := g.deps.Sessions.Store.Ping(ctx); err != nil {
		problems["session_store"] = err.Error()
	}
	if g.deps.OIDC != nil {
		if err := g.deps.OIDC.Ready(ctx); err != nil {
			problems["oidc"] = err.Error()
		}
	}
	if len(problems) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "problems": problems})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "routes": g.deps.Policy.Engine().Routes()})
}

// ---------- passkeys ----------

func (g *Gateway) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, err := g.deps.Sessions.Load(r)
	if err != nil || sess == nil {
		writeError(w, http.StatusUnauthorized, "sign in before registering a passkey")
		return
	}
	if !g.checkCSRF(w, r, sess) {
		return
	}

	creation, sd, err := g.deps.Passkeys.BeginRegistration(r.Context(), passkey.Profile{
		Subject:       sess.Subject,
		Email:         sess.Email,
		EmailVerified: sess.EmailVerified,
		Name:          sess.Name,
		Groups:        sess.Groups,
		Claims:        sess.Claims,
	}, g.now())
	if err != nil {
		g.deps.Log.Error("begin registration", "sub", sess.Subject, "err", err)
		writeError(w, http.StatusInternalServerError, "could not start registration")
		return
	}
	if !g.stashWebAuthn(w, sd) {
		writeError(w, http.StatusInternalServerError, "could not start registration")
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (g *Gateway) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, err := g.deps.Sessions.Load(r)
	if err != nil || sess == nil {
		writeError(w, http.StatusUnauthorized, "no session")
		return
	}
	if !g.checkCSRF(w, r, sess) {
		return
	}
	sd, ok := g.popWebAuthn(w, r)
	if !ok {
		writeError(w, http.StatusBadRequest, "registration challenge missing or expired")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cred, err := g.deps.Passkeys.FinishRegistration(r.Context(), sess.Subject, sd, body)
	if err != nil {
		g.deps.Metrics.AuthEvents.WithLabelValues("passkey_register", "error").Inc()
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "passkey.register_failed", Subject: sess.Subject, Reason: err.Error()})
		writeError(w, http.StatusBadRequest, "registration failed")
		return
	}
	g.deps.Metrics.AuthEvents.WithLabelValues("passkey_register", "ok").Inc()
	g.deps.Audit.Log(r.Context(), r, audit.Record{
		Event: "passkey.registered", Subject: sess.Subject,
		Attrs: []slog.Attr{slog.String("credential_id", fmt.Sprintf("%x", cred.ID))},
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (g *Gateway) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, sd, err := g.deps.Passkeys.BeginLogin()
	if err != nil {
		g.deps.Log.Error("begin passkey login", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start passkey login")
		return
	}
	if !g.stashWebAuthn(w, sd) {
		writeError(w, http.StatusInternalServerError, "could not start passkey login")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (g *Gateway) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	sd, ok := g.popWebAuthn(w, r)
	if !ok {
		writeError(w, http.StatusBadRequest, "login challenge missing or expired")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := g.deps.Passkeys.FinishLogin(r.Context(), sd, body)
	if err != nil {
		g.deps.Metrics.AuthEvents.WithLabelValues("passkey_login", "error").Inc()
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "passkey.login_failed", Reason: err.Error()})
		writeError(w, http.StatusUnauthorized, "passkey login failed")
		return
	}

	now := g.now()
	sess := g.deps.Sessions.New()
	sess.Subject = user.Subject
	sess.Email = user.Email
	sess.EmailVerified = user.EmailVerified
	sess.Name = user.Name
	sess.Groups = user.Groups
	sess.Claims = user.Claims
	sess.AddAMR("passkey")
	sess.StepUpAt = now

	if err := g.deps.Sessions.Commit(w, r, sess); err != nil {
		g.deps.Log.Error("commit session", "err", err)
		writeError(w, http.StatusInternalServerError, "could not persist session")
		return
	}
	g.deps.Metrics.AuthEvents.WithLabelValues("passkey_login", "ok").Inc()
	g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "passkey.login", Subject: sess.Subject})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "subject": sess.Subject, "csrf": sess.CSRFToken})
}

func (g *Gateway) handleStepUpBegin(w http.ResponseWriter, r *http.Request) {
	sess, err := g.deps.Sessions.Load(r)
	if err != nil || sess == nil {
		writeError(w, http.StatusUnauthorized, "no session")
		return
	}
	if !g.checkCSRF(w, r, sess) {
		return
	}
	assertion, sd, err := g.deps.Passkeys.BeginStepUp(r.Context(), sess.Subject)
	if err != nil {
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "passkey.stepup_unavailable", Subject: sess.Subject, Reason: err.Error()})
		writeError(w, http.StatusBadRequest, "no passkey registered for this account")
		return
	}
	if !g.stashWebAuthn(w, sd) {
		writeError(w, http.StatusInternalServerError, "could not start step-up")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (g *Gateway) handleStepUpFinish(w http.ResponseWriter, r *http.Request) {
	sess, err := g.deps.Sessions.Load(r)
	if err != nil || sess == nil {
		writeError(w, http.StatusUnauthorized, "no session")
		return
	}
	if !g.checkCSRF(w, r, sess) {
		return
	}
	sd, ok := g.popWebAuthn(w, r)
	if !ok {
		writeError(w, http.StatusBadRequest, "step-up challenge missing or expired")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := g.deps.Passkeys.FinishStepUp(r.Context(), sess.Subject, sd, body); err != nil {
		g.deps.Metrics.AuthEvents.WithLabelValues("passkey_stepup", "error").Inc()
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "passkey.stepup_failed", Subject: sess.Subject, Reason: err.Error()})
		writeError(w, http.StatusUnauthorized, "step-up failed")
		return
	}

	// Privilege level just increased, so rotate the identifier.
	if err := g.deps.Sessions.Rotate(r.Context(), sess); err != nil {
		g.deps.Log.Error("rotate session", "err", err)
		writeError(w, http.StatusInternalServerError, "could not rotate session")
		return
	}
	sess.StepUpAt = g.now()
	sess.AddAMR("passkey")
	if err := g.deps.Sessions.Commit(w, r, sess); err != nil {
		g.deps.Log.Error("commit session", "err", err)
		writeError(w, http.StatusInternalServerError, "could not persist session")
		return
	}

	g.deps.Metrics.AuthEvents.WithLabelValues("passkey_stepup", "ok").Inc()
	g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "passkey.stepup", Subject: sess.Subject})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "csrf": sess.CSRFToken})
}

// stashWebAuthn seals the challenge into a short-lived cookie. Keeping it out
// of the session store means an unauthenticated passkey login attempt cannot
// write to the store.
func (g *Gateway) stashWebAuthn(w http.ResponseWriter, sd *webauthn.SessionData) bool {
	blob, err := json.Marshal(sd)
	if err != nil {
		return false
	}
	sealed, err := g.deps.Sealer.Seal(webauthnPurpose, blob, webauthnTTL)
	if err != nil {
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stepUpCookie,
		Value:    sealed,
		Path:     Prefix,
		MaxAge:   int(webauthnTTL.Seconds()),
		HttpOnly: true,
		Secure:   g.deps.Config.Secure(),
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

// popWebAuthn reads and immediately invalidates the challenge cookie, so a
// challenge can never be replayed.
func (g *Gateway) popWebAuthn(w http.ResponseWriter, r *http.Request) (webauthn.SessionData, bool) {
	c, err := r.Cookie(stepUpCookie)
	if err != nil {
		return webauthn.SessionData{}, false
	}
	g.clearCookie(w, stepUpCookie, Prefix)

	blob, err := g.deps.Sealer.Open(webauthnPurpose, c.Value)
	if err != nil {
		return webauthn.SessionData{}, false
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(blob, &sd); err != nil {
		return webauthn.SessionData{}, false
	}
	return sd, true
}

// ---------- helpers ----------

// checkCSRF enforces same-origin plus a session-bound token on state-changing
// requests. Both are required: the origin check alone fails open for clients
// that send no Origin or Referer, and the token alone is unavailable before a
// session exists.
func (g *Gateway) checkCSRF(w http.ResponseWriter, r *http.Request, sess *session.Session) bool {
	if !httpx.SameOrigin(r, g.deps.Config.PublicURL) {
		writeError(w, http.StatusForbidden, "cross-origin request rejected")
		return false
	}
	if sess == nil {
		return true
	}
	supplied := r.Header.Get("X-CSRF-Token")
	if !httpx.TokenEqual(supplied, sess.CSRFToken) {
		g.deps.Audit.Log(r.Context(), r, audit.Record{Event: "csrf.rejected", Subject: sess.Subject})
		writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
		return false
	}
	return true
}

func (g *Gateway) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: g.deps.Config.Secure(), SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gateway) requireStepUp(w http.ResponseWriter, r *http.Request, d policy.Decision, sess *session.Session) {
	w.Header().Set("X-Zt-Step-Up", "required")
	if httpx.WantsHTML(r) {
		var csrf string
		if sess != nil {
			csrf = sess.CSRFToken
		}
		g.renderStepUp(w, d, csrf)
		return
	}
	// 401 with a hint, not 403: the client can do something about this.
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error":  "step-up authentication required",
		"route":  d.Route,
		"reason": d.Reason,
		"verify": Prefix + "passkey/stepup/begin",
	})
}

func identityFrom(s *session.Session) *policy.Identity {
	if s == nil {
		return nil
	}
	return &policy.Identity{
		Subject:       s.Subject,
		Email:         s.Email,
		EmailVerified: s.EmailVerified,
		Groups:        s.Groups,
		Claims:        s.Claims,
		StepUpAt:      s.StepUpAt,
	}
}

func applyIdentity(s *session.Session, tok *oidcauth.Tokens) {
	if tok == nil || tok.Identity == nil {
		return
	}
	s.Subject = tok.Identity.Subject
	s.Email = tok.Identity.Email
	s.EmailVerified = tok.Identity.EmailVerified
	s.Name = tok.Identity.Name
	s.Groups = tok.Identity.Groups
	s.Claims = tok.Identity.Claims
	s.IDTokenRaw = tok.IDToken
	s.TokenExpiry = tok.Expiry
	if tok.RefreshToken != "" {
		s.RefreshToken = tok.RefreshToken
	}
}

func subjectOf(s *session.Session) string {
	if s == nil {
		return ""
	}
	return s.Subject
}

func zeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func readBody(r *http.Request) ([]byte, error) {
	// WebAuthn responses are small; bound the read so a large POST cannot
	// exhaust memory.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return nil, errors.New("could not read request body")
	}
	if len(body) == 0 {
		return nil, errors.New("empty request body")
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
