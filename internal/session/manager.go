package session

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const cookiePurpose = "session-cookie"

// Manager ties the Store to the browser cookie and enforces absolute and
// idle lifetimes.
type Manager struct {
	Store       Store
	Sealer      *Sealer
	CookieName  string
	Secure      bool
	TTL         time.Duration
	IdleTimeout time.Duration
	Now         func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// New creates an unsaved session with fresh ID and CSRF token.
func (m *Manager) New() *Session {
	now := m.now()
	return &Session{
		ID:        NewID(),
		CSRFToken: NewID(),
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(m.TTL),
	}
}

// Load returns the session referenced by the request cookie, or
// ErrNotFound. Expired and idle sessions are deleted.
func (m *Manager) Load(r *http.Request) (*Session, error) {
	c, err := r.Cookie(m.CookieName)
	if err != nil {
		return nil, ErrNotFound
	}
	raw, err := m.Sealer.Open(cookiePurpose, c.Value)
	if err != nil {
		return nil, ErrNotFound
	}
	s, err := m.Store.Get(r.Context(), string(raw))
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || now.Sub(s.LastSeen) > m.IdleTimeout {
		_ = m.Store.Delete(r.Context(), s.ID)
		return nil, ErrNotFound
	}
	return s, nil
}

// Touch records activity. To avoid a store write per request it only
// persists when the last write is older than a minute.
func (m *Manager) Touch(ctx context.Context, s *Session) error {
	now := m.now()
	if now.Sub(s.LastSeen) < time.Minute {
		return nil
	}
	s.LastSeen = now
	return m.save(ctx, s)
}

// Commit persists s and sets the session cookie.
func (m *Manager) Commit(w http.ResponseWriter, r *http.Request, s *Session) error {
	s.LastSeen = m.now()
	if err := m.save(r.Context(), s); err != nil {
		return err
	}
	ttl := s.ExpiresAt.Sub(m.now())
	v, err := m.Sealer.Seal(cookiePurpose, []byte(s.ID), ttl)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    v,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Rotate moves s to a new ID, deleting the old record. Call it whenever the
// privilege level changes (login, step-up) to defeat session fixation.
func (m *Manager) Rotate(ctx context.Context, s *Session) error {
	old := s.ID
	s.ID = NewID()
	s.CSRFToken = NewID()
	if old == "" {
		return nil
	}
	if err := m.Store.Delete(ctx, old); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// Destroy deletes the session and clears the cookie.
func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request, s *Session) error {
	m.ClearCookie(w)
	if s == nil {
		return nil
	}
	return m.Store.Delete(r.Context(), s.ID)
}

// ClearCookie expires the session cookie.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: m.CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: m.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) save(ctx context.Context, s *Session) error {
	ttl := s.ExpiresAt.Sub(m.now())
	if ttl <= 0 {
		return ErrNotFound
	}
	return m.Store.Save(ctx, s, ttl)
}
