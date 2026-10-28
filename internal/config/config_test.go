package config

import (
	"strings"
	"testing"
	"time"
)

func base() map[string]string {
	return map[string]string{
		"ZT_PUBLIC_URL":     "https://app.example.com",
		"ZT_UPSTREAM_URL":   "http://upstream:3000",
		"ZT_POLICY_FILE":    "policy.yaml",
		"ZT_OIDC_ISSUER":    "https://idp.example.com",
		"ZT_OIDC_CLIENT_ID": "gateway",
		"ZT_SESSION_SECRET": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
}

func loadMap(m map[string]string) (*Config, error) {
	return load(func(k string) string { return m[k] })
}

func TestLoadDefaults(t *testing.T) {
	c, err := loadMap(base())
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.CookieName != "__Host-zt_session" {
		t.Errorf("cookie name %q", c.Session.CookieName)
	}
	if c.Passkeys.RPID != "app.example.com" {
		t.Errorf("rp id %q", c.Passkeys.RPID)
	}
	if c.JWT.TTL != time.Minute || c.JWT.Audience != "http://upstream:3000" {
		t.Errorf("jwt %+v", c.JWT)
	}
	if !c.Passkeys.Enabled || !c.Secure() {
		t.Error("expected passkeys enabled and secure")
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]struct {
		set  map[string]string
		want string
	}{
		"missing issuer":  {map[string]string{"ZT_OIDC_ISSUER": ""}, "ZT_OIDC_ISSUER is required"},
		"short secret":    {map[string]string{"ZT_SESSION_SECRET": "c2hvcnQ="}, "32 bytes"},
		"bad url":         {map[string]string{"ZT_UPSTREAM_URL": "upstream:3000"}, "absolute http(s) URL"},
		"bad duration":    {map[string]string{"ZT_JWT_TTL": "soon"}, "ZT_JWT_TTL"},
		"long jwt":        {map[string]string{"ZT_JWT_TTL": "1h"}, "(0, 10m]"},
		"redis needs url": {map[string]string{"ZT_SESSION_STORE": "redis"}, "ZT_REDIS_URL"},
		"unknown store":   {map[string]string{"ZT_SESSION_STORE": "disk"}, "memory or redis"},
		"no openid":       {map[string]string{"ZT_OIDC_SCOPES": "email,profile"}, "openid"},
		"path in public":  {map[string]string{"ZT_PUBLIC_URL": "https://a.example.com/app"}, "path"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			for k, v := range tc.set {
				m[k] = v
			}
			_, err := loadMap(m)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestPlainHTTPCookieName(t *testing.T) {
	m := base()
	m["ZT_PUBLIC_URL"] = "http://localhost:8080"
	c, err := loadMap(m)
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.CookieName != "zt_session" {
		t.Fatalf("cookie name %q", c.Session.CookieName)
	}
}
