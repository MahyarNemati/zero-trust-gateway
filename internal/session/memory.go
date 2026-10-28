package session

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// MemoryStore keeps sessions in process. Suitable for a single replica or
// local development; sessions are lost on restart.
type MemoryStore struct {
	mu        sync.Mutex
	items     map[string]memItem
	now       func() time.Time
	nextSweep time.Time
}

type memItem struct {
	data    []byte
	expires time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: map[string]memItem{}, now: time.Now}
}

// Get returns a copy of the session so callers cannot mutate shared state.
func (m *MemoryStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	it, ok := m.items[id]
	m.mu.Unlock()
	if !ok || !m.now().Before(it.expires) {
		return nil, ErrNotFound
	}
	var s Session
	if err := json.Unmarshal(it.data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save stores s until ttl elapses.
func (m *MemoryStore) Save(_ context.Context, s *Session, ttl time.Duration) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.After(m.nextSweep) {
		for k, it := range m.items {
			if !now.Before(it.expires) {
				delete(m.items, k)
			}
		}
		m.nextSweep = now.Add(time.Minute)
	}
	m.items[s.ID] = memItem{data: b, expires: now.Add(ttl)}
	return nil
}

// Delete removes a session.
func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	delete(m.items, id)
	m.mu.Unlock()
	return nil
}

// Ping always succeeds.
func (m *MemoryStore) Ping(context.Context) error { return nil }

// Len returns the number of stored sessions, including expired ones not yet
// swept.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}
