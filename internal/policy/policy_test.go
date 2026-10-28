package policy

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const doc = `
default: deny
routes:
  - name: health
    match:
      paths: ["/healthz"]
      methods: [GET, head]
    allow_anonymous: true
  - name: static
    match:
      paths: ["/static/*"]
    allow_anonymous: true
  - name: admin-writes
    match:
      hosts: ["admin.example.com"]
      paths: ["/api/*"]
      methods: [POST, PUT, DELETE]
    require:
      groups_any: [admins]
      step_up: true
      step_up_max_age: 10m
  - name: admin
    match:
      hosts: ["admin.example.com"]
    require:
      groups_any: [admins, sre]
  - name: billing
    match:
      hosts: ["*.example.com"]
      path_regex: "^/billing/[0-9]+$"
    require:
      groups_all: [finance, employees]
      claims:
        email_verified: true
        acr: [mfa, phishing-resistant]
  - name: staff
    match:
      paths: ["/staff*"]
    require:
      email_domains: [example.com]
  - name: app
    match:
      hosts: ["app.example.com"]
`

var now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestEvaluate(t *testing.T) {
	e, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	admin := &Identity{Subject: "a", Groups: []string{"admins"}}
	adminFresh := &Identity{Subject: "a", Groups: []string{"admins"}, StepUpAt: now.Add(-5 * time.Minute)}
	adminStale := &Identity{Subject: "a", Groups: []string{"admins"}, StepUpAt: now.Add(-11 * time.Minute)}
	sre := &Identity{Subject: "s", Groups: []string{"sre"}}
	user := &Identity{Subject: "u", Groups: []string{"employees"}}
	finance := &Identity{Subject: "f", Groups: []string{"finance", "employees"},
		Claims: map[string]any{"email_verified": true, "acr": "mfa"}}
	financeWeak := &Identity{Subject: "f", Groups: []string{"finance", "employees"},
		Claims: map[string]any{"email_verified": true, "acr": "pwd"}}
	financeListClaim := &Identity{Subject: "f", Groups: []string{"finance", "employees"},
		Claims: map[string]any{"email_verified": true, "acr": []any{"pwd", "phishing-resistant"}}}
	staff := &Identity{Subject: "x", Email: "x@Example.com", EmailVerified: true}
	staffUnverified := &Identity{Subject: "x", Email: "x@example.com"}
	outsider := &Identity{Subject: "o", Email: "o@evil.com", EmailVerified: true}

	cases := []struct {
		name   string
		method string
		url    string
		id     *Identity
		want   Outcome
		route  string
	}{
		{"anonymous health", "GET", "http://app.example.com/healthz", nil, Allow, "health"},
		{"method matching is case-insensitive", "HEAD", "http://app.example.com/healthz", nil, Allow, "health"},
		{"health POST falls through to app", "POST", "http://app.example.com/healthz", nil, Login, "app"},
		{"static prefix", "GET", "http://other.test/static/app.js", nil, Allow, "static"},
		{"admin write needs session", "POST", "http://admin.example.com/api/users", nil, Login, "admin-writes"},
		{"admin write needs step-up", "POST", "http://admin.example.com/api/users", admin, StepUp, "admin-writes"},
		{"admin write with fresh step-up", "POST", "http://admin.example.com/api/users", adminFresh, Allow, "admin-writes"},
		{"admin write with stale step-up", "DELETE", "http://admin.example.com/api/users/1", adminStale, StepUp, "admin-writes"},
		{"sre cannot write", "POST", "http://admin.example.com/api/users", sre, Deny, "admin-writes"},
		{"sre can read", "GET", "http://admin.example.com/api/users", sre, Allow, "admin"},
		{"host with port", "GET", "http://admin.example.com:8443/", sre, Allow, "admin"},
		{"user denied on admin", "GET", "http://admin.example.com/", user, Deny, "admin"},
		{"billing all groups and claims", "GET", "http://app.example.com/billing/42", finance, Allow, "billing"},
		{"billing claim mismatch", "GET", "http://app.example.com/billing/42", financeWeak, Deny, "billing"},
		{"billing list claim", "GET", "http://app.example.com/billing/42", financeListClaim, Allow, "billing"},
		{"billing missing group", "GET", "http://app.example.com/billing/42", user, Deny, "billing"},
		{"billing regex miss falls through", "GET", "http://app.example.com/billing/abc", user, Allow, "app"},
		{"wildcard does not match apex", "GET", "http://example.com/billing/1", finance, Deny, "default"},
		{"staff domain", "GET", "http://x.test/staff/home", staff, Allow, "staff"},
		{"staff unverified email", "GET", "http://x.test/staff", staffUnverified, Deny, "staff"},
		{"staff wrong domain", "GET", "http://x.test/staff", outsider, Deny, "staff"},
		{"unknown host denied", "GET", "http://unknown.test/", user, Deny, "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.url, nil)
			d := e.Evaluate(r, c.id, now)
			if d.Outcome != c.want || d.Route != c.route {
				t.Fatalf("got %s via %q (%s), want %s via %q", d.Outcome, d.Route, d.Reason, c.want, c.route)
			}
		})
	}
}

func TestDefaultAuthenticated(t *testing.T) {
	e, err := Parse([]byte("default: authenticated\n"))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/anything", nil)
	if d := e.Evaluate(r, nil, now); d.Outcome != Login {
		t.Fatalf("anonymous: %s", d.Outcome)
	}
	if d := e.Evaluate(r, &Identity{Subject: "u"}, now); d.Outcome != Allow {
		t.Fatalf("authenticated: %s", d.Outcome)
	}
}

func TestDefaultStepUpMaxAge(t *testing.T) {
	e, err := Parse([]byte("routes:\n  - match: {paths: [\"/x\"]}\n    require: {step_up: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/x", nil)
	id := &Identity{Subject: "u", StepUpAt: now.Add(-DefaultStepUpMaxAge + time.Second)}
	if d := e.Evaluate(r, id, now); d.Outcome != Allow {
		t.Fatalf("got %s", d.Outcome)
	}
	id.StepUpAt = now.Add(-DefaultStepUpMaxAge - time.Second)
	if d := e.Evaluate(r, id, now); d.Outcome != StepUp {
		t.Fatalf("got %s", d.Outcome)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"unknown field":      {"routes:\n  - name: a\n    requires: {}\n", "field requires not found"},
		"bad default":        {"default: allow\n", "default must be"},
		"anon with require":  {"routes:\n  - allow_anonymous: true\n    require: {groups_any: [a]}\n", "allow_anonymous cannot"},
		"relative path":      {"routes:\n  - match: {paths: [api]}\n", "must start with /"},
		"bad regex":          {"routes:\n  - match: {path_regex: \"(\"}\n", "path_regex"},
		"bad wildcard":       {"routes:\n  - match: {hosts: [\"a.*.com\"]}\n", "wildcard"},
		"duplicate names":    {"routes:\n  - name: a\n  - name: a\n", "duplicate"},
		"nested claim value": {"routes:\n  - require: {claims: {a: {b: c}}}\n", "scalar or a list"},
		"negative max age":   {"routes:\n  - require: {step_up: true, step_up_max_age: -1m}\n", "negative"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	e, err := Parse([]byte(doc))
	if err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://app.example.com/billing/42", nil)
	id := &Identity{Subject: "f", Groups: []string{"finance", "employees"},
		Claims: map[string]any{"email_verified": true, "acr": "mfa"}}
	b.ReportAllocs()
	for b.Loop() {
		e.Evaluate(r, id, now)
	}
}
