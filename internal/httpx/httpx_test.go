package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSafeRedirect(t *testing.T) {
	cases := map[string]string{
		"":                      "/",
		"/app?x=1#f":            "/app?x=1#f",
		"//evil.com":            "/",
		"/\\evil.com":           "/",
		"https://evil.com/":     "/",
		"javascript:alert(1)":   "/",
		"relative":              "/",
		"/ok/path":              "/ok/path",
		"/a\r\nSet-Cookie: x=1": "/",
	}
	for in, want := range cases {
		if got := SafeRedirect(in); got != want {
			t.Errorf("SafeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	origin, _ := url.Parse("https://gw.example.com")
	cases := []struct {
		name   string
		header map[string]string
		want   bool
	}{
		{"matching origin", map[string]string{"Origin": "https://gw.example.com"}, true},
		{"other origin", map[string]string{"Origin": "https://evil.example.com"}, false},
		{"scheme downgrade", map[string]string{"Origin": "http://gw.example.com"}, false},
		{"referer fallback", map[string]string{"Referer": "https://gw.example.com/.zt/login"}, true},
		{"bad referer", map[string]string{"Referer": "https://evil.example.com/gw.example.com"}, false},
		{"neither", nil, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		for k, v := range c.header {
			r.Header.Set(k, v)
		}
		if got := SameOrigin(r, origin); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Referrer-Policy", "no-referrer")
	BaselineSecurityHeaders(h, true)
	if h.Get("Referrer-Policy") != "no-referrer" {
		t.Error("upstream header overridden")
	}
	if h.Get("Strict-Transport-Security") == "" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("baseline missing: %v", h)
	}
	p := http.Header{}
	PageSecurityHeaders(p, false)
	if p.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS on plain HTTP")
	}
	if p.Get("Content-Security-Policy") == "" || p.Get("X-Frame-Options") != "DENY" {
		t.Error("page headers missing")
	}
}

func TestRequestIDsIgnoreInbound(t *testing.T) {
	var seen string
	h := RequestIDs(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = RequestID(r.Context()) }))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(RequestIDHeader, "forged")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if seen == "" || seen == "forged" || w.Header().Get(RequestIDHeader) != seen {
		t.Fatalf("request id %q", seen)
	}
}

func TestWantsHTML(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !WantsHTML(r) {
		t.Error("browser GET")
	}
	r = httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Accept", "text/html")
	if WantsHTML(r) {
		t.Error("POST should not redirect")
	}
	r = httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Accept", "application/json")
	if WantsHTML(r) {
		t.Error("API client")
	}
}
