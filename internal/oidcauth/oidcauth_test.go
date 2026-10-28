package oidcauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/MahyarNemati/zero-trust-gateway/internal/testutil/mockidp"
)

func authorize(t *testing.T, c *Client, state, nonce, verifier string) string {
	t.Helper()
	u, err := c.AuthCodeURL(context.Background(), state, nonce, verifier)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("state") != state {
		t.Fatalf("redirect %q", resp.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

func setup(t *testing.T) (*mockidp.Provider, *Client) {
	idp := mockidp.New("gw", "s3cret")
	t.Cleanup(idp.Close)
	idp.SetUser(mockidp.User{Subject: "u1", Email: "u1@example.com", Name: "U One",
		Groups: []string{"eng"}, Extra: map[string]any{"acr": "mfa"}})
	c := New(Config{Issuer: idp.URL, ClientID: "gw", ClientSecret: "s3cret",
		RedirectURL: "http://gw.test/.zt/oidc/callback", Scopes: []string{"openid", "email"}})
	return idp, c
}

func TestCodeFlowWithPKCE(t *testing.T) {
	idp, c := setup(t)
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier-verifier-123"
	code := authorize(t, c, "state1", "nonce1", verifier)

	if req := idp.Requests[0]; req.Get("code_challenge_method") != "S256" || req.Get("nonce") != "nonce1" {
		t.Fatalf("authorization request missing PKCE or nonce: %v", req)
	}

	tok, err := c.Exchange(ctx, code, verifier, "nonce1")
	if err != nil {
		t.Fatal(err)
	}
	id := tok.Identity
	if id.Subject != "u1" || !id.EmailVerified || id.Groups[0] != "eng" || id.Claims["acr"] != "mfa" || id.Name != "U One" {
		t.Fatalf("identity %+v", id)
	}
	if _, ok := id.Claims["nonce"]; ok {
		t.Fatal("protocol claims should be stripped")
	}
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}

	idp.UpdateGroups([]string{"eng", "admins"})
	ref, err := c.Refresh(ctx, tok.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Identity == nil || len(ref.Identity.Groups) != 2 || ref.RefreshToken == tok.RefreshToken {
		t.Fatalf("refresh %+v", ref)
	}

	idp.RevokeAll()
	if _, err := c.Refresh(ctx, ref.RefreshToken); err == nil {
		t.Fatal("revoked refresh token accepted")
	}
	if c.EndSessionURL(ctx) != idp.URL+"/logout" {
		t.Fatal("end session endpoint not discovered")
	}
}

func TestExchangeRejects(t *testing.T) {
	_, c := setup(t)
	ctx := context.Background()
	verifier := "verifier-verifier-verifier-verifier-verifier-123"

	code := authorize(t, c, "s", "n", verifier)
	if _, err := c.Exchange(ctx, code, "wrong-verifier-wrong-verifier-wrong-verifier-12", "n"); err == nil {
		t.Fatal("wrong PKCE verifier accepted")
	}

	code = authorize(t, c, "s", "n", verifier)
	if _, err := c.Exchange(ctx, code, verifier, "other"); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("nonce mismatch: %v", err)
	}

	code = authorize(t, c, "s", "n", verifier)
	if _, err := c.Exchange(ctx, code, verifier, "n"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(ctx, code, verifier, "n"); err == nil {
		t.Fatal("code replay accepted")
	}
}

func TestLazyDiscovery(t *testing.T) {
	c := New(Config{Issuer: "http://127.0.0.1:1", ClientID: "x"})
	if err := c.Ready(context.Background()); err == nil {
		t.Fatal("unreachable issuer reported ready")
	}
}
