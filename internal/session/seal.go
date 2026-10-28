package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidToken is returned for sealed values that fail authentication,
// were sealed for another purpose, or have expired.
var ErrInvalidToken = errors.New("session: invalid or expired token")

// Sealer encrypts and authenticates small values for cookies with
// AES-256-GCM. Each purpose derives its own key, so a value sealed for one
// cookie can never be replayed as another.
type Sealer struct {
	master []byte
	now    func() time.Time
}

// NewSealer returns a Sealer for a 32-byte master secret.
func NewSealer(secret []byte) (*Sealer, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("session: secret must be 32 bytes, got %d", len(secret))
	}
	return &Sealer{master: secret, now: time.Now}, nil
}

func (s *Sealer) aead(purpose string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, s.master, nil, "zt-gateway/"+purpose, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext so that it can only be opened for purpose until
// ttl elapses.
func (s *Sealer) Seal(purpose string, plaintext []byte, ttl time.Duration) (string, error) {
	aead, err := s.aead(purpose)
	if err != nil {
		return "", err
	}
	body := make([]byte, 8+len(plaintext))
	binary.BigEndian.PutUint64(body, uint64(s.now().Add(ttl).Unix()))
	copy(body[8:], plaintext)

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(body)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, body, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open reverses Seal.
func (s *Sealer) Open(purpose, token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	aead, err := s.aead(purpose)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns+8+aead.Overhead() {
		return nil, ErrInvalidToken
	}
	body, err := aead.Open(nil, raw[:ns], raw[ns:], []byte(purpose))
	if err != nil {
		return nil, ErrInvalidToken
	}
	exp := int64(binary.BigEndian.Uint64(body))
	if s.now().Unix() > exp {
		return nil, ErrInvalidToken
	}
	return body[8:], nil
}
