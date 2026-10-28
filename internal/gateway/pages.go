package gateway

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/MahyarNemati/zero-trust-gateway/internal/httpx"
	"github.com/MahyarNemati/zero-trust-gateway/internal/policy"
)

// Interstitial pages are rendered server-side. Styles are inline but the
// passkey script is served from a same-origin path under the reserved prefix,
// so the Content-Security-Policy set by httpx.PageSecurityHeaders does not
// need to allow inline script.
//
//go:embed assets/passkey.js
var assetFS embed.FS

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .Title }}</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #fff; --border: #e2e5ea; --text: #16191d;
    --muted: #6b7280; --accent: #2f6fed; --danger: #d93f3f;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0d0f12; --card: #16191e; --border: #272b33; --text: #ecedef; --muted: #9aa1ad;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: var(--bg); color: var(--text); padding: 24px;
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  main {
    width: 100%; max-width: 420px; background: var(--card);
    border: 1px solid var(--border); border-radius: 12px; padding: 28px;
  }
  h1 { margin: 0 0 6px; font-size: 1.15rem; }
  p { margin: 0 0 18px; color: var(--muted); }
  .row { display: flex; flex-direction: column; gap: 10px; }
  button, a.btn {
    display: block; width: 100%; padding: 11px 14px; border-radius: 8px;
    border: 1px solid var(--border); background: var(--card); color: var(--text);
    font: inherit; font-weight: 600; text-align: center; text-decoration: none; cursor: pointer;
  }
  button.primary, a.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button[disabled] { opacity: .55; cursor: default; }
  .err { color: var(--danger); font-size: .85rem; min-height: 1.2em; margin-top: 12px; }
  .meta { margin-top: 18px; font-size: .78rem; color: var(--muted); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; }
</style>
</head>
<body>
<main>
  <h1>{{ .Heading }}</h1>
  <p>{{ .Message }}</p>

  <div class="row">
    {{ if .ShowPasskey }}
      <button id="passkey" class="primary" type="button">{{ .PasskeyLabel }}</button>
    {{ end }}
    {{ if .ShowOIDC }}
      <a class="btn{{ if not .ShowPasskey }} primary{{ end }}" href="{{ .LoginURL }}">Continue with single sign-on</a>
    {{ end }}
  </div>

  <div class="err" id="err" role="alert"></div>

  {{ if .Route }}<div class="meta">Route <code>{{ .Route }}</code>{{ if .Reason }} &middot; {{ .Reason }}{{ end }}</div>{{ end }}
</main>

{{ if .ShowPasskey }}
<script src="{{ .ScriptURL }}" data-begin="{{ .BeginURL }}" data-finish="{{ .FinishURL }}" data-csrf="{{ .CSRF }}"></script>
{{ end }}
</body>
</html>`))

type pageData struct {
	Title        string
	Heading      string
	Message      string
	Route        string
	Reason       string
	ShowPasskey  bool
	PasskeyLabel string
	ShowOIDC     bool
	LoginURL     string
	ScriptURL    string
	BeginURL     string
	FinishURL    string
	CSRF         string
}

func (g *Gateway) renderPage(w http.ResponseWriter, code int, d pageData) {
	httpx.PageSecurityHeaders(w.Header(), g.deps.Config.Secure())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pageTmpl.Execute(w, d)
}

func (g *Gateway) renderDenied(w http.ResponseWriter, d policy.Decision) {
	g.renderPage(w, http.StatusForbidden, pageData{
		Title:   "Access denied",
		Heading: "Access denied",
		Message: "Your account does not meet the requirements for this resource. If you believe this is wrong, contact whoever owns it.",
		Route:   d.Route,
		Reason:  d.Reason,
	})
}

func (g *Gateway) renderStepUp(w http.ResponseWriter, d policy.Decision, csrf string) {
	g.renderPage(w, http.StatusUnauthorized, pageData{
		Title:        "Verification required",
		Heading:      "Verify it is you",
		Message:      "This resource needs a fresh passkey check, even though you are already signed in.",
		Route:        d.Route,
		Reason:       d.Reason,
		ShowPasskey:  g.deps.Passkeys != nil,
		PasskeyLabel: "Verify with a passkey",
		ScriptURL:    Prefix + "passkey.js",
		BeginURL:     Prefix + "passkey/stepup/begin",
		FinishURL:    Prefix + "passkey/stepup/finish",
		CSRF:         csrf,
	})
}

// renderSignIn offers the available authentication methods.
func (g *Gateway) renderSignIn(w http.ResponseWriter, redirect string) {
	loginURL := Prefix + "login"
	if redirect != "" && redirect != "/" {
		loginURL += "?rd=" + url.QueryEscape(redirect)
	}
	g.renderPage(w, http.StatusUnauthorized, pageData{
		Title:        "Sign in",
		Heading:      "Sign in",
		Message:      "This resource requires an authenticated session.",
		ShowPasskey:  g.deps.Passkeys != nil,
		PasskeyLabel: "Sign in with a passkey",
		ShowOIDC:     g.deps.OIDC != nil,
		LoginURL:     loginURL,
		ScriptURL:    Prefix + "passkey.js",
		BeginURL:     Prefix + "passkey/login/begin",
		FinishURL:    Prefix + "passkey/login/finish",
	})
}

// handleAsset serves the passkey script. It is immutable for a day: the file
// is embedded in the binary, so a new version means a new deployment.
func (g *Gateway) handleAsset(w http.ResponseWriter, r *http.Request) {
	body, err := assetFS.ReadFile("assets/passkey.js")
	if err != nil {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	http.ServeContent(w, r, "passkey.js", buildTime, newBytesReader(body))
}

var buildTime = time.Now()

func newBytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
