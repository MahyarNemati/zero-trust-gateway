// Package httpx holds HTTP plumbing shared by the gateway: request IDs,
// security headers, CSRF checks and safe redirect targets.
package httpx

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

type ctxKey struct{}

// WithRequestID stores id in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestID returns the request ID stored in ctx.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// RequestIDHeader carries the request ID to the upstream and the client.
const RequestIDHeader = "X-Request-Id"

// RequestIDs assigns every request an ID. Inbound IDs are not trusted,
// since clients could use them to forge audit correlation.
func RequestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [12]byte
		_, _ = rand.Read(b[:])
		id := hex.EncodeToString(b[:])
		r.Header.Set(RequestIDHeader, id)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// PageSecurityHeaders are applied to pages the gateway renders itself.
func PageSecurityHeaders(h http.Header, secure bool) {
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	BaselineSecurityHeaders(h, secure)
}

// BaselineSecurityHeaders fills in headers that are safe for any response
// without overriding values the upstream chose.
func BaselineSecurityHeaders(h http.Header, secure bool) {
	setDefault(h, "X-Content-Type-Options", "nosniff")
	setDefault(h, "Referrer-Policy", "strict-origin-when-cross-origin")
	setDefault(h, "Cross-Origin-Opener-Policy", "same-origin")
	if secure {
		setDefault(h, "Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}

func setDefault(h http.Header, k, v string) {
	if h.Get(k) == "" {
		h.Set(k, v)
	}
}

// SameOrigin reports whether an unsafe request came from a page on origin.
// It requires Origin, falling back to Referer for older clients, and rejects
// requests that carry neither.
func SameOrigin(r *http.Request, origin *url.URL) bool {
	want := origin.Scheme + "://" + origin.Host
	if o := r.Header.Get("Origin"); o != "" {
		return o == want
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Scheme+"://"+u.Host == want
	}
	return false
}

// TokenEqual compares CSRF tokens in constant time.
func TokenEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SafeRedirect returns rd if it is a local absolute path, otherwise "/".
// It rejects scheme-relative and backslash tricks that browsers would
// resolve to another host.
func SafeRedirect(rd string) string {
	if rd == "" || rd[0] != '/' || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") ||
		strings.ContainsAny(rd, "\r\n\t") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return rd
}

// WantsHTML reports whether the client is a browser navigation that can
// follow a redirect to the login page.
func WantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
