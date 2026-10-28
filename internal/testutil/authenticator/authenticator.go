// Package authenticator is a software WebAuthn authenticator for tests. It
// produces "none" attestation registration responses and ES256 assertions
// that go-webauthn verifies exactly as it would a hardware key.
package authenticator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

type credential struct {
	id     []byte
	priv   *ecdsa.PrivateKey
	user   []byte
	rpID   string
	counts uint32
}

// Authenticator holds generated credentials.
type Authenticator struct {
	Origin string
	creds  []*credential
	// SkipUV omits the user-verified flag, to test policy enforcement.
	SkipUV bool
}

// New returns an authenticator that reports origin in client data.
func New(origin string) *Authenticator { return &Authenticator{Origin: origin} }

// CreationOptions is the subset of PublicKeyCredentialCreationOptions used.
type CreationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

// RequestOptions is the subset of PublicKeyCredentialRequestOptions used.
type RequestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

var b64 = base64.RawURLEncoding

func decode(s string) ([]byte, error) {
	if b, err := b64.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// Create answers a navigator.credentials.create() call. optionsJSON is the
// JSON the relying party sent.
func (a *Authenticator) Create(optionsJSON []byte) ([]byte, error) {
	var opts CreationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, err
	}
	pk := opts.PublicKey
	user, err := decode(pk.User.ID)
	if err != nil {
		return nil, fmt.Errorf("user id: %w", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	c := &credential{id: make([]byte, 32), priv: priv, user: user, rpID: pk.RP.ID}
	if _, err := rand.Read(c.id); err != nil {
		return nil, err
	}

	cose, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: priv.PublicKey.X.FillBytes(make([]byte, 32)),
		-3: priv.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		return nil, err
	}
	authData := a.authData(c.rpID, flagAT, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(c.id)))
	authData = append(authData, c.id...)
	authData = append(authData, cose...)

	attObj, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		return nil, err
	}
	clientData, err := a.clientData("webauthn.create", pk.Challenge)
	if err != nil {
		return nil, err
	}
	a.creds = append(a.creds, c)
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.id), "rawId": b64.EncodeToString(c.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
}

// Get answers a navigator.credentials.get() call.
func (a *Authenticator) Get(optionsJSON []byte) ([]byte, error) {
	var opts RequestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, err
	}
	pk := opts.PublicKey
	c := a.pick(pk.RPID, pk.AllowCredentials)
	if c == nil {
		return nil, errors.New("authenticator: no matching credential")
	}
	c.counts++
	authData := a.authData(c.rpID, 0, c.counts)
	clientData, err := a.clientData("webauthn.get", pk.Challenge)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.priv, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.id), "rawId": b64.EncodeToString(c.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.user),
		},
		"clientExtensionResults": map[string]any{},
	})
}

// ResetCounter rewinds a credential's signature counter, simulating a clone.
func (a *Authenticator) ResetCounter() {
	for _, c := range a.creds {
		c.counts = 0
	}
}

func (a *Authenticator) pick(rpID string, allow []struct {
	ID string `json:"id"`
}) *credential {
	for _, c := range a.creds {
		if c.rpID != rpID {
			continue
		}
		if len(allow) == 0 {
			return c
		}
		for _, x := range allow {
			if id, err := decode(x.ID); err == nil && string(id) == string(c.id) {
				return c
			}
		}
	}
	return nil
}

func (a *Authenticator) authData(rpID string, extra byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := byte(flagUP) | extra
	if !a.SkipUV {
		flags |= flagUV
	}
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, count)
}

func (a *Authenticator) clientData(typ, challenge string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false,
	})
}
