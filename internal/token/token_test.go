package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/MahyarNemati/zero-trust-gateway/internal/session"
)

func testSession() *session.Session {
	return &session.Session{
		Subject: "user-1", Email: "a@example.com", EmailVerified: true, Name: "A",
		Groups: []string{"admins"}, AMR: []string{"oidc", "passkey"},
		StepUpAt: time.Unix(1_700_000_000, 0),
	}
}

func TestMintVerify(t *testing.T) {
	kr, err := NewRotatingKeyring(time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_100, 0)
	iss := &Issuer{Keys: kr, Issuer: "https://gw.example.com", Audience: "app", TTL: time.Minute, Now: func() time.Time { return now }}
	raw, err := iss.Mint(testSession())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(raw, kr.JWKS(), "https://gw.example.com", "app", now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.Groups[0] != "admins" || c.StepUpAt != 1_700_000_000 || len(c.AMR) != 2 {
		t.Fatalf("claims %+v", c)
	}
	if _, err := Verify(raw, kr.JWKS(), "https://gw.example.com", "other-app", now); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := Verify(raw, kr.JWKS(), "https://gw.example.com", "app", now.Add(61*time.Second)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := Verify(raw[:len(raw)-4]+"AAAA", kr.JWKS(), "https://gw.example.com", "app", now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func kids(set jose.JSONWebKeySet) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

func TestRotation(t *testing.T) {
	kr, err := NewRotatingKeyring(time.Hour, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	kr.now = func() time.Time { return now }
	iss := &Issuer{Keys: kr, Issuer: "gw", Audience: "app", TTL: time.Minute, Now: func() time.Time { return now }}

	first := kr.CurrentID()
	next := kids(kr.JWKS())[1]
	oldToken, _ := iss.Mint(testSession())

	if err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	if kr.CurrentID() != next {
		t.Fatal("pre-published next key was not promoted")
	}
	set := kr.JWKS()
	if len(set.Keys) != 3 || !strings.Contains(strings.Join(kids(set), ","), first) {
		t.Fatalf("after rotation want current, next and retiring keys, got %v", kids(set))
	}
	if _, err := Verify(oldToken, set, "gw", "app", now); err != nil {
		t.Fatalf("token from previous key must verify during retention: %v", err)
	}

	now = now.Add(3 * time.Minute)
	if err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(kids(kr.JWKS()), ","), first) {
		t.Fatal("retired key still published after retention")
	}
}

func TestStaticKeyring(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := NewStaticKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	id := kr.CurrentID()
	_ = kr.Rotate()
	if kr.CurrentID() != id || len(kr.JWKS().Keys) != 1 {
		t.Fatal("static keyring must not rotate")
	}
	if err := os.WriteFile(path, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStaticKeyring(path); err == nil {
		t.Fatal("junk key accepted")
	}
}

func TestJWKSHandler(t *testing.T) {
	kr, _ := NewRotatingKeyring(time.Hour, time.Minute)
	w := httptest.NewRecorder()
	JWKSHandler(kr).ServeHTTP(w, httptest.NewRequest("GET", "/.zt/jwks.json", nil))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 || set.Keys[0].IsPublic() == false {
		t.Fatalf("jwks %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"d"`) {
		t.Fatal("private key material in JWKS")
	}
}
