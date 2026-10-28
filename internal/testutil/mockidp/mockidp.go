// Package mockidp is a minimal in-process OpenID Connect provider for
// tests. It implements discovery, JWKS, the authorization endpoint (which
// signs in a preconfigured user without a UI), and the token endpoint with
// PKCE and refresh tokens.
package mockidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// User is the identity the provider signs in.
type User struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	Extra   map[string]any
}

type grant struct {
	user        User
	clientID    string
	redirectURI string
	nonce       string
	challenge   string
}

// Provider is a running mock IdP.
type Provider struct {
	*httptest.Server
	ClientID     string
	ClientSecret string
	TokenTTL     time.Duration

	mu       sync.Mutex
	key      *rsa.PrivateKey
	user     User
	codes    map[string]grant
	refresh  map[string]grant
	Requests []url.Values // authorization requests, for assertions
}

// New starts a provider for the given client credentials.
func New(clientID, clientSecret string) *Provider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	p := &Provider{
		ClientID: clientID, ClientSecret: clientSecret, TokenTTL: 5 * time.Minute,
		key: key, codes: map[string]grant{}, refresh: map[string]grant{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewServer(mux)
	return p
}

// SetUser sets who the next authorization request signs in.
func (p *Provider) SetUser(u User) {
	p.mu.Lock()
	p.user = u
	p.mu.Unlock()
}

// RevokeAll invalidates every refresh token.
func (p *Provider) RevokeAll() {
	p.mu.Lock()
	p.refresh = map[string]grant{}
	p.mu.Unlock()
}

// UpdateGroups changes the groups returned on the next refresh.
func (p *Provider) UpdateGroups(groups []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, g := range p.refresh {
		g.user.Groups = groups
		p.refresh[k] = g
	}
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/keys",
		"end_session_endpoint":                  p.URL + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.key.PublicKey, KeyID: "mock", Algorithm: "RS256", Use: "sig"},
	}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	p.Requests = append(p.Requests, q)
	user := p.user
	p.mu.Unlock()

	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" {
		http.Error(w, "bad client or response_type", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	code := randString()
	p.mu.Lock()
	p.codes[code] = grant{user: user, clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"),
		nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	p.mu.Unlock()

	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		oauthError(w, "invalid_client")
		return
	}

	var g grant
	p.mu.Lock()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		var found bool
		g, found = p.codes[code]
		delete(p.codes, code)
		p.mu.Unlock()
		if !found || g.redirectURI != r.PostForm.Get("redirect_uri") {
			oauthError(w, "invalid_grant")
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			oauthError(w, "invalid_grant")
			return
		}
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		var found bool
		g, found = p.refresh[rt]
		delete(p.refresh, rt)
		p.mu.Unlock()
		if !found {
			oauthError(w, "invalid_grant")
			return
		}
		g.nonce = ""
	default:
		p.mu.Unlock()
		oauthError(w, "unsupported_grant_type")
		return
	}

	idToken, err := p.sign(g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rt := randString()
	p.mu.Lock()
	p.refresh[rt] = g
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  randString(),
		"token_type":    "Bearer",
		"expires_in":    int(p.TokenTTL.Seconds()),
		"refresh_token": rt,
		"id_token":      idToken,
	})
}

func (p *Provider) sign(g grant) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256,
		Key: jose.JSONWebKey{Key: p.key, KeyID: "mock"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.URL, "sub": g.user.Subject, "aud": g.clientID,
		"iat": now.Unix(), "exp": now.Add(p.TokenTTL).Unix(),
		"email": g.user.Email, "email_verified": g.user.Email != "",
		"name": g.user.Name, "groups": g.user.Groups,
	}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	for k, v := range g.user.Extra {
		claims[k] = v
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func oauthError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randString() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
