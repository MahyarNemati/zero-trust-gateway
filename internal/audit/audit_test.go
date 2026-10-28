package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/MahyarNemati/zero-trust-gateway/internal/httpx"
)

func TestLogWritesJSONLine(t *testing.T) {
	var buf bytes.Buffer
	a := New(&buf)
	r := httptest.NewRequest("POST", "http://gw.test/admin?x=1", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	ctx := httpx.WithRequestID(context.Background(), "req-1")
	a.Log(ctx, r, Record{Event: AccessDenied, Subject: "u1", Route: "admin", Reason: "missing group",
		Attrs: []slog.Attr{slog.Bool("step_up", false)}})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %q", buf.String())
	}
	want := map[string]any{"log": "audit", "event": "access.deny", "sub": "u1", "route": "admin",
		"reason": "missing group", "client_ip": "203.0.113.9", "method": "POST", "path": "/admin",
		"host": "gw.test", "request_id": "req-1", "step_up": false}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["ts"]; !ok {
		t.Error("missing ts")
	}
	if _, ok := got["level"]; ok {
		t.Error("level should be omitted")
	}
}
