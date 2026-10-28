// Package token issues the short-lived JWT the gateway forwards to the
// upstream, and publishes the verification keys as a JWKS.
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type key struct {
	id      string
	priv    crypto.Signer
	retires time.Time // zero while current or next
}

// Keyring holds the signing keys. With rotation enabled it always publishes
// three generations: the retiring key (until tokens it signed have expired),
// the current signing key, and the next key, which is published one full
// interval before it starts signing so verifiers with cached JWKS already
// know it.
type Keyring struct {
	mu       sync.RWMutex
	current  *key
	next     *key
	retiring []*key
	static   bool
	interval time.Duration
	retain   time.Duration
	now      func() time.Time
}

// NewRotatingKeyring generates ES256 keys that rotate every interval. Old
// keys stay published for retain, which must cover the token lifetime plus
// verifier clock skew.
func NewRotatingKeyring(interval, retain time.Duration) (*Keyring, error) {
	if interval <= 0 || retain <= 0 {
		return nil, errors.New("token: rotation interval and retention must be positive")
	}
	cur, err := generate()
	if err != nil {
		return nil, err
	}
	nxt, err := generate()
	if err != nil {
		return nil, err
	}
	return &Keyring{current: cur, next: nxt, interval: interval, retain: retain, now: time.Now}, nil
}

// NewStaticKeyring loads one EC P-256 private key from a PEM file. Use it
// when several replicas must sign with the same key; rotation is then done
// by deploying a new file.
func NewStaticKeyring(path string) (*Keyring, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	k, err := parsePEM(b)
	if err != nil {
		return nil, err
	}
	return &Keyring{current: k, static: true, now: time.Now}, nil
}

func parsePEM(b []byte) (*key, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("token: no PEM block in signing key file")
	}
	var priv any
	var err error
	switch blk.Type {
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("token: unsupported PEM block %q", blk.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("token: parse signing key: %w", err)
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("token: signing key must be an EC P-256 key")
	}
	return &key{id: thumbprint(&ec.PublicKey), priv: ec}, nil
}

func generate() (*key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("token: generate key: %w", err)
	}
	return &key{id: thumbprint(&priv.PublicKey), priv: priv}, nil
}

// thumbprint is the RFC 7638 JWK thumbprint, a stable kid derived from the
// public key.
func thumbprint(pub *ecdsa.PublicKey) string {
	jwk := jose.JSONWebKey{Key: pub}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		sum := sha256.Sum256(elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y))
		tp = sum[:]
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// Rotate promotes the next key to current and generates a new next key.
func (k *Keyring) Rotate() error {
	if k.static {
		return nil
	}
	nxt, err := generate()
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	old := k.current
	old.retires = now.Add(k.retain)
	k.retiring = append(k.pruned(now), old)
	k.current, k.next = k.next, nxt
	return nil
}

func (k *Keyring) pruned(now time.Time) []*key {
	out := k.retiring[:0]
	for _, r := range k.retiring {
		if now.Before(r.retires) {
			out = append(out, r)
		}
	}
	return out
}

// Run rotates keys every interval until ctx is done.
func (k *Keyring) Run(ctx context.Context, log *slog.Logger) {
	if k.static {
		return
	}
	t := time.NewTicker(k.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := k.Rotate(); err != nil {
				log.Error("signing key rotation failed", "err", err)
				continue
			}
			log.Info("signing key rotated", "kid", k.CurrentID())
		}
	}
}

// CurrentID returns the kid of the active signing key.
func (k *Keyring) CurrentID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current.id
}

func (k *Keyring) signingKey() *key {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current
}

// JWKS returns the public keys verifiers should accept.
func (k *Keyring) JWKS() jose.JSONWebKeySet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	now := k.now()
	var set jose.JSONWebKeySet
	add := func(x *key) {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key: x.priv.Public(), KeyID: x.id, Algorithm: string(jose.ES256), Use: "sig",
		})
	}
	add(k.current)
	if k.next != nil {
		add(k.next)
	}
	for _, r := range k.retiring {
		if now.Before(r.retires) {
			add(r)
		}
	}
	return set
}
