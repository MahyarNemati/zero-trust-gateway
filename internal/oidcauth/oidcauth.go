// Package oidcauth runs the OpenID Connect authorization code flow with
// PKCE against the configured identity provider.
package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrNonceMismatch means the ID token was not issued for this login attempt.
var ErrNonceMismatch = errors.New("oidcauth: nonce mismatch")

// Config describes the relying party.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	GroupsClaim  string
}

// Identity is the subset of ID token claims the gateway uses.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
	Claims        map[string]any
}

// Tokens is the result of a code exchange or refresh.
type Tokens struct {
	Identity     *Identity
	RefreshToken string
	Expiry       time.Time
	IDToken      string
}

// Client talks to the identity provider. Discovery happens lazily and is
// retried on failure, so the gateway can start before the IdP is reachable.
type Client struct {
	cfg Config

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	endSess  string
}

// New returns a Client. Call Ready or any flow method to trigger discovery.
func New(cfg Config) *Client {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &Client{cfg: cfg}
}

func (c *Client) discover(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.oauth, c.verifier, nil
	}
	p, err := oidc.NewProvider(ctx, c.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidcauth: discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&extra)

	c.provider = p
	c.endSess = extra.EndSession
	c.oauth = &oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		RedirectURL:  c.cfg.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       c.cfg.Scopes,
	}
	c.verifier = p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID})
	return c.oauth, c.verifier, nil
}

// Ready reports whether discovery has succeeded, attempting it if not.
func (c *Client) Ready(ctx context.Context) error {
	_, _, err := c.discover(ctx)
	return err
}

// AuthCodeURL builds the authorization request. verifier is the PKCE code
// verifier; only its S256 challenge leaves the gateway.
func (c *Client) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	oc, _, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	return oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange redeems the authorization code and verifies the ID token,
// including its nonce.
func (c *Client) Exchange(ctx context.Context, code, verifier, nonce string) (*Tokens, error) {
	oc, v, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("oidcauth: token response has no id_token")
	}
	idt, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: id token: %w", err)
	}
	if idt.Nonce != nonce {
		return nil, ErrNonceMismatch
	}
	id, err := c.identity(idt)
	if err != nil {
		return nil, err
	}
	return &Tokens{Identity: id, RefreshToken: tok.RefreshToken, Expiry: idt.Expiry, IDToken: raw}, nil
}

// Refresh uses a refresh token to confirm the user is still active at the
// IdP and to pick up changed claims such as group membership. When the
// response carries no new ID token, Identity is nil and the caller keeps
// the claims it has.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	oc, v, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := oc.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("oidcauth: refresh: %w", err)
	}
	out := &Tokens{RefreshToken: tok.RefreshToken, Expiry: tok.Expiry}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	if raw, ok := tok.Extra("id_token").(string); ok && raw != "" {
		idt, err := v.Verify(ctx, raw)
		if err != nil {
			return nil, fmt.Errorf("oidcauth: refreshed id token: %w", err)
		}
		if out.Identity, err = c.identity(idt); err != nil {
			return nil, err
		}
		out.Expiry, out.IDToken = idt.Expiry, raw
	}
	return out, nil
}

// EndSessionURL returns the IdP logout endpoint, or "" if it has none.
func (c *Client) EndSessionURL(ctx context.Context) string {
	if _, _, err := c.discover(ctx); err != nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endSess
}

func (c *Client) identity(idt *oidc.IDToken) (*Identity, error) {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidcauth: claims: %w", err)
	}
	id := &Identity{Subject: idt.Subject, Claims: claims}
	id.Email, _ = claims["email"].(string)
	id.EmailVerified, _ = claims["email_verified"].(bool)
	id.Name, _ = claims["name"].(string)
	if id.Name == "" {
		id.Name, _ = claims["preferred_username"].(string)
	}
	switch g := claims[c.cfg.GroupsClaim].(type) {
	case []any:
		for _, x := range g {
			if s, ok := x.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	case string:
		id.Groups = []string{g}
	}
	// Drop protocol claims; policies match on user attributes.
	for _, k := range []string{"iss", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash", "azp", "sid", "auth_time", "jti"} {
		delete(claims, k)
	}
	return id, nil
}
