// Package session manages gateway login sessions.
//
// The browser holds only an encrypted, authenticated session ID. Identity,
// tokens and step-up state live server side in a Store, which makes logout
// and revocation immediate and keeps IdP refresh tokens out of the browser.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// ErrNotFound is returned when a session does not exist or has expired.
var ErrNotFound = errors.New("session: not found")

// Session is the server-side state of one login.
type Session struct {
	ID            string         `json:"id"`
	Subject       string         `json:"sub"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	Name          string         `json:"name,omitempty"`
	Groups        []string       `json:"groups,omitempty"`
	Claims        map[string]any `json:"claims,omitempty"`
	// AMR lists how the user authenticated, in order: "oidc", "passkey".
	AMR []string `json:"amr"`

	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenExpiry  time.Time `json:"token_expiry,omitzero"`
	IDTokenRaw   string    `json:"id_token,omitempty"`

	CSRFToken string    `json:"csrf"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	StepUpAt  time.Time `json:"step_up_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store persists sessions.
type Store interface {
	Get(ctx context.Context, id string) (*Session, error)
	// Save writes s and expires it after ttl.
	Save(ctx context.Context, s *Session, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
	Ping(ctx context.Context) error
}

// NewID returns a 256-bit random identifier.
func NewID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("session: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// HasAMR reports whether the session used method m.
func (s *Session) HasAMR(m string) bool {
	for _, a := range s.AMR {
		if a == m {
			return true
		}
	}
	return false
}

// AddAMR records method m once.
func (s *Session) AddAMR(m string) {
	if !s.HasAMR(m) {
		s.AMR = append(s.AMR, m)
	}
}
