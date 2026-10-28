package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore keeps sessions in Redis so any gateway replica can serve any
// user.
type RedisStore struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisStore returns a store using rdb with keys under prefix.
func NewRedisStore(rdb redis.UniversalClient, prefix string) *RedisStore {
	if prefix == "" {
		prefix = "zt:session:"
	}
	return &RedisStore{rdb: rdb, prefix: prefix}
}

// Get loads a session.
func (r *RedisStore) Get(ctx context.Context, id string) (*Session, error) {
	b, err := r.rdb.Get(ctx, r.prefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session: redis get: %w", err)
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("session: decode: %w", err)
	}
	return &s, nil
}

// Save writes a session with a TTL.
func (r *RedisStore) Save(ctx context.Context, s *Session, ttl time.Duration) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := r.rdb.Set(ctx, r.prefix+s.ID, b, ttl).Err(); err != nil {
		return fmt.Errorf("session: redis set: %w", err)
	}
	return nil
}

// Delete removes a session.
func (r *RedisStore) Delete(ctx context.Context, id string) error {
	if err := r.rdb.Del(ctx, r.prefix+id).Err(); err != nil {
		return fmt.Errorf("session: redis del: %w", err)
	}
	return nil
}

// Ping checks connectivity.
func (r *RedisStore) Ping(ctx context.Context) error { return r.rdb.Ping(ctx).Err() }
