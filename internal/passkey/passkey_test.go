package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/MahyarNemati/zero-trust-gateway/internal/testutil/authenticator"
)

const origin = "https://gw.example.com"

func stores(t *testing.T) map[string]Store {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	out := map[string]Store{"memory": NewMemoryStore(), "miniredis": NewRedisStore(rdb, "")}
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		real := redis.NewClient(&redis.Options{Addr: addr})
		t.Cleanup(func() { _ = real.Close() })
		out["redis"] = NewRedisStore(real, "zt:test:"+time.Now().Format("150405.000000")+":")
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCeremonies(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			svc, err := New(Config{RPID: "gw.example.com", RPDisplayName: "GW", Origins: []string{origin}}, st)
			if err != nil {
				t.Fatal(err)
			}
			auth := authenticator.New(origin)
			profile := Profile{Subject: "u1", Email: "u1@example.com", Name: "U", Groups: []string{"eng"}}

			// Registration.
			opts, sd, err := svc.BeginRegistration(ctx, profile, now)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := auth.Create(mustJSON(t, opts))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.FinishRegistration(ctx, "u1", *sd, resp); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.FinishRegistration(ctx, "u1", *sd, resp); err == nil {
				t.Fatal("replayed registration accepted")
			}
			if u, _ := st.BySubject(ctx, "u1"); len(u.Credentials) != 1 {
				t.Fatalf("want 1 credential, got %d", len(u.Credentials))
			}

			// Profile sync updates the snapshot.
			profile.Groups = []string{"eng", "admins"}
			if err := svc.SyncProfile(ctx, profile, now); err != nil {
				t.Fatal(err)
			}

			// Discoverable login.
			aopts, asd, err := svc.BeginLogin()
			if err != nil {
				t.Fatal(err)
			}
			aresp, err := auth.Get(mustJSON(t, aopts))
			if err != nil {
				t.Fatal(err)
			}
			u, err := svc.FinishLogin(ctx, *asd, aresp)
			if err != nil {
				t.Fatal(err)
			}
			if u.Subject != "u1" || len(u.Groups) != 2 {
				t.Fatalf("login returned %+v", u)
			}

			// A challenge cannot be reused.
			if _, err := svc.FinishLogin(ctx, *asd, aresp); err == nil {
				t.Fatal("replayed assertion accepted")
			}

			// Step-up for the same user.
			sopts, ssd, err := svc.BeginStepUp(ctx, "u1")
			if err != nil {
				t.Fatal(err)
			}
			sresp, err := auth.Get(mustJSON(t, sopts))
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.FinishStepUp(ctx, "u1", *ssd, sresp); err != nil {
				t.Fatal(err)
			}

			// A cloned authenticator is detected by its counter.
			auth.ResetCounter()
			sopts, ssd, _ = svc.BeginStepUp(ctx, "u1")
			sresp, _ = auth.Get(mustJSON(t, sopts))
			if err := svc.FinishStepUp(ctx, "u1", *ssd, sresp); !errors.Is(err, ErrCloned) {
				t.Fatalf("clone not detected: %v", err)
			}
		})
	}
}

func TestRejectsWrongOriginAndMissingUV(t *testing.T) {
	ctx := context.Background()
	svc, err := New(Config{RPID: "gw.example.com", RPDisplayName: "GW", Origins: []string{origin}}, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Subject: "u1"}

	opts, sd, _ := svc.BeginRegistration(ctx, p, time.Now())
	evil := authenticator.New("https://evil.example.net")
	resp, _ := evil.Create(mustJSON(t, opts))
	if _, err := svc.FinishRegistration(ctx, "u1", *sd, resp); err == nil {
		t.Fatal("wrong origin accepted")
	}

	opts, sd, _ = svc.BeginRegistration(ctx, p, time.Now())
	noUV := authenticator.New(origin)
	noUV.SkipUV = true
	resp, _ = noUV.Create(mustJSON(t, opts))
	if _, err := svc.FinishRegistration(ctx, "u1", *sd, resp); err == nil {
		t.Fatal("registration without user verification accepted")
	}

	if _, _, err := svc.BeginStepUp(ctx, "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("step-up for unknown user: %v", err)
	}
	if _, _, err := svc.BeginStepUp(ctx, "u1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("step-up without credentials: %v", err)
	}
}
