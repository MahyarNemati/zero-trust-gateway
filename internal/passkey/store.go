package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

// ErrUserNotFound is returned for unknown subjects or user handles.
var ErrUserNotFound = errors.New("passkey: user not found")

// User is a gateway account that can hold passkeys. It is keyed by the
// IdP subject and carries a snapshot of the profile from the last OIDC
// login, which is what a passkey-only login restores.
type User struct {
	Handle        []byte                `json:"handle"`
	Subject       string                `json:"sub"`
	Email         string                `json:"email,omitempty"`
	EmailVerified bool                  `json:"email_verified,omitempty"`
	Name          string                `json:"name,omitempty"`
	Groups        []string              `json:"groups,omitempty"`
	Claims        map[string]any        `json:"claims,omitempty"`
	Credentials   []webauthn.Credential `json:"credentials"`
	ProfileAt     time.Time             `json:"profile_at"`
}

// WebAuthnID implements webauthn.User.
func (u *User) WebAuthnID() []byte { return u.Handle }

// WebAuthnName implements webauthn.User.
func (u *User) WebAuthnName() string {
	if u.Email != "" {
		return u.Email
	}
	return u.Subject
}

// WebAuthnDisplayName implements webauthn.User.
func (u *User) WebAuthnDisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.WebAuthnName()
}

// WebAuthnCredentials implements webauthn.User.
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// Store persists users and their credentials.
type Store interface {
	BySubject(ctx context.Context, sub string) (*User, error)
	ByHandle(ctx context.Context, handle []byte) (*User, error)
	Save(ctx context.Context, u *User) error
}

// MemoryStore is an in-process Store.
type MemoryStore struct {
	mu      sync.RWMutex
	bySub   map[string][]byte
	handles map[string]string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{bySub: map[string][]byte{}, handles: map[string]string{}}
}

// BySubject loads a user by IdP subject.
func (m *MemoryStore) BySubject(_ context.Context, sub string) (*User, error) {
	m.mu.RLock()
	b, ok := m.bySub[sub]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrUserNotFound
	}
	var u User
	return &u, json.Unmarshal(b, &u)
}

// ByHandle loads a user by WebAuthn user handle.
func (m *MemoryStore) ByHandle(ctx context.Context, h []byte) (*User, error) {
	m.mu.RLock()
	sub, ok := m.handles[string(h)]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrUserNotFound
	}
	return m.BySubject(ctx, sub)
}

// Save stores a user.
func (m *MemoryStore) Save(_ context.Context, u *User) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.bySub[u.Subject] = b
	m.handles[string(u.Handle)] = u.Subject
	m.mu.Unlock()
	return nil
}

// RedisStore keeps users in Redis as JSON with a handle index.
type RedisStore struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisStore returns a Redis-backed Store.
func NewRedisStore(rdb redis.UniversalClient, prefix string) *RedisStore {
	if prefix == "" {
		prefix = "zt:passkey:"
	}
	return &RedisStore{rdb: rdb, prefix: prefix}
}

// BySubject loads a user by IdP subject.
func (r *RedisStore) BySubject(ctx context.Context, sub string) (*User, error) {
	b, err := r.rdb.Get(ctx, r.prefix+"user:"+sub).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("passkey: redis get: %w", err)
	}
	var u User
	return &u, json.Unmarshal(b, &u)
}

// ByHandle loads a user by WebAuthn user handle.
func (r *RedisStore) ByHandle(ctx context.Context, h []byte) (*User, error) {
	sub, err := r.rdb.Get(ctx, r.prefix+"handle:"+fmt.Sprintf("%x", h)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("passkey: redis get: %w", err)
	}
	return r.BySubject(ctx, sub)
}

// Save stores a user and its handle index atomically.
func (r *RedisStore) Save(ctx context.Context, u *User) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, r.prefix+"user:"+u.Subject, b, 0)
		p.Set(ctx, r.prefix+"handle:"+fmt.Sprintf("%x", u.Handle), u.Subject, 0)
		return nil
	})
	if err != nil {
		return fmt.Errorf("passkey: redis save: %w", err)
	}
	return nil
}
