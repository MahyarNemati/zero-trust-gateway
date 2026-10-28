// Package passkey implements WebAuthn registration, passwordless login and
// step-up verification on top of go-webauthn.
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrCloned is returned when an authenticator's signature counter goes
// backwards, which indicates a cloned credential.
var ErrCloned = errors.New("passkey: authenticator counter regressed, credential may be cloned")

// Service runs WebAuthn ceremonies.
type Service struct {
	wa    *webauthn.WebAuthn
	store Store
}

// Config describes the relying party.
type Config struct {
	RPID          string
	RPDisplayName string
	Origins       []string
	Timeout       time.Duration
}

// New returns a Service.
func New(cfg Config, store Store) (*Service, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	to := webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts:              webauthn.TimeoutsConfig{Login: to, Registration: to},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Service{wa: wa, store: store}, nil
}

// Profile is the identity snapshot stored with a user.
type Profile struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
	Claims        map[string]any
}

// SyncProfile records the latest IdP profile for a subject that already has
// passkeys, so a later passkey-only login restores current attributes.
func (s *Service) SyncProfile(ctx context.Context, p Profile, now time.Time) error {
	u, err := s.store.BySubject(ctx, p.Subject)
	if errors.Is(err, ErrUserNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	applyProfile(u, p, now)
	return s.store.Save(ctx, u)
}

func applyProfile(u *User, p Profile, now time.Time) {
	u.Email, u.EmailVerified, u.Name = p.Email, p.EmailVerified, p.Name
	u.Groups, u.Claims, u.ProfileAt = p.Groups, p.Claims, now
}

// User returns the stored user for a subject.
func (s *Service) User(ctx context.Context, sub string) (*User, error) {
	return s.store.BySubject(ctx, sub)
}

// BeginRegistration starts adding a passkey for an authenticated user.
func (s *Service) BeginRegistration(ctx context.Context, p Profile, now time.Time) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	u, err := s.store.BySubject(ctx, p.Subject)
	if errors.Is(err, ErrUserNotFound) {
		u = &User{Handle: make([]byte, 32), Subject: p.Subject}
		if _, err := rand.Read(u.Handle); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	applyProfile(u, p, now)
	if err := s.store.Save(ctx, u); err != nil {
		return nil, nil, err
	}
	return s.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.Credentials).CredentialDescriptors()))
}

// FinishRegistration verifies the attestation response and stores the
// credential.
func (s *Service) FinishRegistration(ctx context.Context, sub string, sd webauthn.SessionData, body []byte) (*webauthn.Credential, error) {
	u, err := s.store.BySubject(ctx, sub)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(u.Handle, sd.UserID) {
		return nil, errors.New("passkey: registration ceremony belongs to another user")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("passkey: parse attestation: %w", describe(err))
	}
	cred, err := s.wa.CreateCredential(u, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("passkey: verify attestation: %w", describe(err))
	}
	for _, c := range u.Credentials {
		if bytes.Equal(c.ID, cred.ID) {
			return nil, errors.New("passkey: credential already registered")
		}
	}
	u.Credentials = append(u.Credentials, *cred)
	if err := s.store.Save(ctx, u); err != nil {
		return nil, err
	}
	return cred, nil
}

// BeginLogin starts a usernameless (discoverable credential) login.
func (s *Service) BeginLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
}

// FinishLogin verifies a discoverable assertion and returns its owner.
func (s *Service) FinishLogin(ctx context.Context, sd webauthn.SessionData, body []byte) (*User, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("passkey: parse assertion: %w", describe(err))
	}
	var owner *User
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, err := s.store.ByHandle(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		owner = u
		return u, nil
	}
	cred, err := s.wa.ValidateDiscoverableLogin(handler, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("passkey: verify assertion: %w", describe(err))
	}
	return owner, s.recordUse(ctx, owner, cred)
}

// BeginStepUp asks a signed-in user to re-verify with one of their
// passkeys.
func (s *Service) BeginStepUp(ctx context.Context, sub string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	u, err := s.store.BySubject(ctx, sub)
	if err != nil {
		return nil, nil, err
	}
	if len(u.Credentials) == 0 {
		return nil, nil, ErrUserNotFound
	}
	return s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
}

// FinishStepUp verifies the step-up assertion for sub.
func (s *Service) FinishStepUp(ctx context.Context, sub string, sd webauthn.SessionData, body []byte) error {
	u, err := s.store.BySubject(ctx, sub)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return fmt.Errorf("passkey: parse assertion: %w", describe(err))
	}
	cred, err := s.wa.ValidateLogin(u, sd, parsed)
	if err != nil {
		return fmt.Errorf("passkey: verify assertion: %w", describe(err))
	}
	return s.recordUse(ctx, u, cred)
}

func (s *Service) recordUse(ctx context.Context, u *User, cred *webauthn.Credential) error {
	if cred.Authenticator.CloneWarning {
		return ErrCloned
	}
	for i := range u.Credentials {
		if bytes.Equal(u.Credentials[i].ID, cred.ID) {
			u.Credentials[i].Authenticator.SignCount = cred.Authenticator.SignCount
			u.Credentials[i].Flags = cred.Flags
		}
	}
	return s.store.Save(ctx, u)
}

// describe surfaces the detailed reason go-webauthn keeps in DevInfo.
func describe(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return fmt.Errorf("%w: %s", err, pe.DevInfo)
	}
	return err
}
