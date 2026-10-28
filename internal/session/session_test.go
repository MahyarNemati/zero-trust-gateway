package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func TestSealer(t *testing.T) {
	s, err := NewSealer(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	tok, err := s.Seal("a", []byte("hello"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open("a", tok)
	if err != nil || string(got) != "hello" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := s.Open("b", tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("cross-purpose open: %v", err)
	}
	tampered := []byte(tok)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := s.Open("a", string(tampered)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered open: %v", err)
	}
	if _, err := s.Open("a", "not base64!"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("garbage open: %v", err)
	}
	other, _ := NewSealer([]byte(strings.Repeat("x", 32)))
	if _, err := other.Open("a", tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("other key open: %v", err)
	}
	now = now.Add(61 * time.Second)
	if _, err := s.Open("a", tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired open: %v", err)
	}
	if _, err := NewSealer([]byte("short")); err == nil {
		t.Fatal("short secret accepted")
	}
}

func stores(t *testing.T) map[string]Store {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	out := map[string]Store{
		"memory":    NewMemoryStore(),
		"miniredis": NewRedisStore(rdb, ""),
	}
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		real := redis.NewClient(&redis.Options{Addr: addr})
		t.Cleanup(func() { _ = real.Close() })
		out["redis"] = NewRedisStore(real, "zt:test:"+NewID()[:8]+":")
	}
	return out
}

func TestStores(t *testing.T) {
	ctx := context.Background()
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			if err := st.Ping(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing: %v", err)
			}
			s := &Session{ID: NewID(), Subject: "u1", Groups: []string{"a", "b"},
				Claims: map[string]any{"acr": "mfa"}, AMR: []string{"oidc"}, CreatedAt: time.Now().UTC().Truncate(time.Second)}
			if err := st.Save(ctx, s, time.Minute); err != nil {
				t.Fatal(err)
			}
			got, err := st.Get(ctx, s.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Subject != "u1" || len(got.Groups) != 2 || got.Claims["acr"] != "mfa" || !got.CreatedAt.Equal(s.CreatedAt) {
				t.Fatalf("round trip mismatch: %+v", got)
			}
			got.Subject = "mutated"
			if again, _ := st.Get(ctx, s.ID); again.Subject != "u1" {
				t.Fatal("store returned shared state")
			}
			if err := st.Delete(ctx, s.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Get(ctx, s.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("after delete: %v", err)
			}
		})
	}
}

func TestMemoryStoreExpiry(t *testing.T) {
	st := NewMemoryStore()
	now := time.Unix(1_700_000_000, 0)
	st.now = func() time.Time { return now }
	ctx := context.Background()
	_ = st.Save(ctx, &Session{ID: "a"}, time.Minute)
	now = now.Add(time.Minute)
	if _, err := st.Get(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	now = now.Add(2 * time.Minute)
	_ = st.Save(ctx, &Session{ID: "b"}, time.Minute)
	if st.Len() != 1 {
		t.Fatalf("sweep left %d sessions", st.Len())
	}
}

func newManager(t *testing.T, now *time.Time) *Manager {
	t.Helper()
	sealer, err := NewSealer(secret)
	if err != nil {
		t.Fatal(err)
	}
	sealer.now = func() time.Time { return *now }
	st := NewMemoryStore()
	st.now = func() time.Time { return *now }
	return &Manager{Store: st, Sealer: sealer, CookieName: "zt", Secure: true,
		TTL: time.Hour, IdleTimeout: 10 * time.Minute, Now: func() time.Time { return *now }}
}

func roundTrip(t *testing.T, m *Manager, s *Session) *http.Request {
	t.Helper()
	w := httptest.NewRecorder()
	if err := m.Commit(w, httptest.NewRequest("GET", "/", nil), s); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("cookie attributes: %+v", c)
	}
	if strings.Contains(c.Value, s.ID) {
		t.Fatal("cookie leaks the session id")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	return r
}

func TestManagerLifecycle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newManager(t, &now)
	s := m.New()
	s.Subject = "u1"
	r := roundTrip(t, m, s)

	got, err := m.Load(r)
	if err != nil || got.Subject != "u1" {
		t.Fatalf("load: %+v %v", got, err)
	}

	now = now.Add(5 * time.Minute)
	if err := m.Touch(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if _, err := m.Load(r); err != nil {
		t.Fatalf("touched session should survive: %v", err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := m.Load(r); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idle session: %v", err)
	}
}

func TestManagerAbsoluteExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newManager(t, &now)
	m.IdleTimeout = 2 * time.Hour
	s := m.New()
	r := roundTrip(t, m, s)
	now = now.Add(59 * time.Minute)
	if _, err := m.Load(r); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := m.Load(r); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
}

func TestManagerRotateAndDestroy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newManager(t, &now)
	s := m.New()
	oldReq := roundTrip(t, m, s)
	oldCSRF := s.CSRFToken
	if err := m.Rotate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if s.CSRFToken == oldCSRF {
		t.Fatal("csrf token not rotated")
	}
	newReq := roundTrip(t, m, s)
	if _, err := m.Load(oldReq); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old cookie still valid after rotate: %v", err)
	}
	if _, err := m.Load(newReq); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := m.Destroy(w, newReq, s); err != nil {
		t.Fatal(err)
	}
	if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Fatalf("cookie not cleared: %v", c)
	}
	if _, err := m.Load(newReq); !errors.Is(err, ErrNotFound) {
		t.Fatalf("destroyed session loads: %v", err)
	}
}

func TestForgedCookie(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newManager(t, &now)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "zt", Value: NewID()})
	if _, err := m.Load(r); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forged cookie: %v", err)
	}
}
