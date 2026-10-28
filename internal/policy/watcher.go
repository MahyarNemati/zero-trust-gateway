package policy

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Store holds the active Engine and swaps it atomically on reload, so
// in-flight requests always see one consistent policy.
type Store struct {
	path     string
	current  atomic.Pointer[Engine]
	log      *slog.Logger
	onReload func(err error)
}

// NewStore loads path and returns a Store serving it.
func NewStore(path string, log *slog.Logger, onReload func(error)) (*Store, error) {
	e, err := Load(path)
	if err != nil {
		return nil, err
	}
	if onReload == nil {
		onReload = func(error) {}
	}
	s := &Store{path: path, log: log, onReload: onReload}
	s.current.Store(e)
	return s, nil
}

// Engine returns the active policy.
func (s *Store) Engine() *Engine { return s.current.Load() }

// Reload re-reads the file. On error the previous policy stays active.
func (s *Store) Reload() error {
	e, err := Load(s.path)
	s.onReload(err)
	if err != nil {
		s.log.Error("policy reload failed, keeping previous policy", "path", s.path, "err", err)
		return err
	}
	s.current.Store(e)
	s.log.Info("policy reloaded", "path", s.path, "routes", e.Routes())
	return nil
}

// Watch reloads the policy whenever the file changes until ctx is done.
//
// It watches the parent directory rather than the file: editors and
// Kubernetes ConfigMap updates replace the file via rename, which drops a
// watch on the file itself. Events are debounced because a single save can
// emit several.
func (s *Store) Watch(ctx context.Context, debounce time.Duration) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("policy watch: %w", err)
	}
	defer w.Close()
	dir := filepath.Dir(s.path)
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("policy watch %s: %w", dir, err)
	}
	name := filepath.Base(s.path)

	var timer *time.Timer
	var fire <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			// ConfigMap mounts swap a "..data" symlink; treat any change in
			// the directory that could affect our file as relevant.
			base := filepath.Base(ev.Name)
			if base != name && base != "..data" {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
			} else {
				timer.Reset(debounce)
			}
			fire = timer.C
		case <-fire:
			fire = nil
			_ = s.Reload()
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			s.log.Warn("policy watcher error", "err", err)
		}
	}
}
