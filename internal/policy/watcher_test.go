package policy

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	write := func(s string) {
		t.Helper()
		// Write then rename, the way editors and ConfigMaps update files.
		tmp := filepath.Join(dir, ".policy.tmp")
		if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	write("default: deny\n")

	var failures atomic.Int32
	s, err := NewStore(path, slog.New(slog.NewTextHandler(io.Discard, nil)), func(err error) {
		if err != nil {
			failures.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Watch(ctx, 20*time.Millisecond) }()
	time.Sleep(50 * time.Millisecond)

	r := httptest.NewRequest("GET", "/", nil)
	id := &Identity{Subject: "u"}
	if d := s.Engine().Evaluate(r, id, now); d.Outcome != Deny {
		t.Fatalf("initial: %s", d.Outcome)
	}

	write("default: authenticated\n")
	waitFor(t, func() bool { return s.Engine().Evaluate(r, id, now).Outcome == Allow })

	write("default: sometimes\n")
	waitFor(t, func() bool { return failures.Load() > 0 })
	if d := s.Engine().Evaluate(r, id, now); d.Outcome != Allow {
		t.Fatalf("invalid file must keep previous policy, got %s", d.Outcome)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
