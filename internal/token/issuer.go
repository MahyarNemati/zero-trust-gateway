package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/MahyarNemati/zero-trust-gateway/internal/session"
)

// Claims is the payload forwarded upstream.
type Claims struct {
	jwt.Claims
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	StepUpAt      int64    `json:"step_up_at,omitempty"`
}

// Issuer mints upstream assertions.
type Issuer struct {
	Keys     *Keyring
	Issuer   string
	Audience string
	TTL      time.Duration
	Now      func() time.Time
}

func (i *Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Mint signs an assertion for the session's user.
func (i *Issuer) Mint(s *session.Session) (string, error) {
	k := i.Keys.signingKey()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.id}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("token: signer: %w", err)
	}
	now := i.now()
	c := Claims{
		Claims: jwt.Claims{
			Issuer:    i.Issuer,
			Subject:   s.Subject,
			Audience:  jwt.Audience{i.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			Expiry:    jwt.NewNumericDate(now.Add(i.TTL)),
			ID:        session.NewID()[:22],
		},
		Email:         s.Email,
		EmailVerified: s.EmailVerified,
		Name:          s.Name,
		Groups:        s.Groups,
		AMR:           s.AMR,
	}
	if !s.StepUpAt.IsZero() {
		c.StepUpAt = s.StepUpAt.Unix()
	}
	return jwt.Signed(signer).Claims(c).Serialize()
}

// Verify checks a token against a JWKS the way an upstream service would.
func Verify(raw string, set jose.JSONWebKeySet, issuer, audience string, now time.Time) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("token: expected one signature")
	}
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) == 0 {
		return nil, fmt.Errorf("token: unknown kid %q", tok.Headers[0].KeyID)
	}
	var c Claims
	if err := tok.Claims(keys[0].Key, &c); err != nil {
		return nil, err
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{audience}, Time: now}, 0); err != nil {
		return nil, err
	}
	return &c, nil
}

// JWKSHandler serves the key set with a short cache lifetime so verifiers
// pick up rotations promptly.
func JWKSHandler(k *Keyring) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(k.JWKS())
	})
}
