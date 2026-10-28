// Package audit writes security events as one JSON object per line, kept
// separate from the operational log so it can be shipped and retained on its
// own terms.
package audit

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/MahyarNemati/zero-trust-gateway/internal/httpx"
)

// Event names.
const (
	LoginSuccess      = "login.success"
	LoginFailure      = "login.failure"
	Logout            = "logout"
	PasskeyRegistered = "passkey.registered"
	PasskeyLogin      = "passkey.login"
	PasskeyFailure    = "passkey.failure"
	StepUpSuccess     = "stepup.success"
	SessionRefreshed  = "session.refreshed"
	SessionRevoked    = "session.revoked"
	AccessAllowed     = "access.allow"
	AccessDenied      = "access.deny"
	AccessNeedsLogin  = "access.login_required"
	AccessNeedsStepUp = "access.stepup_required"
	CSRFRejected      = "csrf.rejected"
)

// Logger records audit events.
type Logger struct {
	l *slog.Logger
}

// New returns a Logger that writes JSON lines to w.
func New(w io.Writer) *Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String("ts", a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			if a.Key == slog.MessageKey {
				a.Key = "event"
			}
			if a.Key == slog.LevelKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return &Logger{l: slog.New(h).With("log", "audit")}
}

// Discard returns a Logger that drops everything.
func Discard() *Logger { return New(io.Discard) }

// Record is one audit entry.
type Record struct {
	Event   string
	Subject string
	Route   string
	Reason  string
	Attrs   []slog.Attr
}

// Log writes rec with request context: client address, method, path, host
// and request ID.
func (a *Logger) Log(ctx context.Context, r *http.Request, rec Record) {
	attrs := []slog.Attr{
		slog.String("request_id", httpx.RequestID(ctx)),
		slog.String("client_ip", clientIP(r)),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path),
	}
	if rec.Subject != "" {
		attrs = append(attrs, slog.String("sub", rec.Subject))
	}
	if rec.Route != "" {
		attrs = append(attrs, slog.String("route", rec.Route))
	}
	if rec.Reason != "" {
		attrs = append(attrs, slog.String("reason", rec.Reason))
	}
	attrs = append(attrs, rec.Attrs...)
	a.l.LogAttrs(ctx, slog.LevelInfo, rec.Event, attrs...)
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
