// Package config loads gateway settings from the environment.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the complete gateway configuration.
type Config struct {
	ListenAddr  string
	MetricsAddr string
	PublicURL   *url.URL
	UpstreamURL *url.URL
	PolicyFile  string
	LogLevel    slog.Level

	OIDC     OIDC
	Session  Session
	JWT      JWT
	Passkeys Passkeys
}

// OIDC holds identity provider settings.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	GroupsClaim  string
}

// Session holds session and cookie settings.
type Session struct {
	Secret      []byte
	Store       string
	RedisURL    string
	TTL         time.Duration
	IdleTimeout time.Duration
	CookieName  string
}

// JWT holds settings for the assertion forwarded upstream.
type JWT struct {
	TTL              time.Duration
	Audience         string
	Header           string
	RotationInterval time.Duration
	SigningKeyFile   string
}

// Passkeys holds WebAuthn settings.
type Passkeys struct {
	Enabled       bool
	RPID          string
	RPDisplayName string
	StepUpMaxAge  time.Duration
}

// Load reads the configuration from the environment.
func Load() (*Config, error) { return load(os.Getenv) }

func load(getenv func(string) string) (*Config, error) {
	e := &env{get: getenv}
	c := &Config{
		ListenAddr:  e.str("ZT_LISTEN_ADDR", ":8080"),
		MetricsAddr: e.str("ZT_METRICS_ADDR", ":9090"),
		PublicURL:   e.url("ZT_PUBLIC_URL", true),
		UpstreamURL: e.url("ZT_UPSTREAM_URL", true),
		PolicyFile:  e.required("ZT_POLICY_FILE"),
		LogLevel:    e.level("ZT_LOG_LEVEL", slog.LevelInfo),
		OIDC: OIDC{
			Issuer:       e.required("ZT_OIDC_ISSUER"),
			ClientID:     e.required("ZT_OIDC_CLIENT_ID"),
			ClientSecret: e.str("ZT_OIDC_CLIENT_SECRET", ""),
			Scopes:       e.list("ZT_OIDC_SCOPES", []string{"openid", "profile", "email"}),
			GroupsClaim:  e.str("ZT_OIDC_GROUPS_CLAIM", "groups"),
		},
		Session: Session{
			Secret:      e.secret("ZT_SESSION_SECRET"),
			Store:       e.str("ZT_SESSION_STORE", "memory"),
			RedisURL:    e.str("ZT_REDIS_URL", ""),
			TTL:         e.duration("ZT_SESSION_TTL", 12*time.Hour),
			IdleTimeout: e.duration("ZT_SESSION_IDLE_TIMEOUT", time.Hour),
			CookieName:  e.str("ZT_COOKIE_NAME", ""),
		},
		JWT: JWT{
			TTL:              e.duration("ZT_JWT_TTL", time.Minute),
			Audience:         e.str("ZT_JWT_AUDIENCE", ""),
			Header:           e.str("ZT_JWT_HEADER", "X-ZT-Assertion"),
			RotationInterval: e.duration("ZT_JWT_ROTATION_INTERVAL", 24*time.Hour),
			SigningKeyFile:   e.str("ZT_JWT_SIGNING_KEY_FILE", ""),
		},
		Passkeys: Passkeys{
			Enabled:       e.bool("ZT_PASSKEYS_ENABLED", true),
			RPID:          e.str("ZT_WEBAUTHN_RP_ID", ""),
			RPDisplayName: e.str("ZT_WEBAUTHN_RP_NAME", "Zero Trust Gateway"),
			StepUpMaxAge:  e.duration("ZT_STEP_UP_MAX_AGE", 15*time.Minute),
		},
	}
	if err := errors.Join(e.errs...); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Secure reports whether the gateway is served over HTTPS.
func (c *Config) Secure() bool { return c.PublicURL.Scheme == "https" }

func (c *Config) applyDefaults() {
	if c.Session.CookieName == "" {
		// The __Host- prefix pins the cookie to this exact origin, but
		// browsers only accept it over HTTPS.
		if c.Secure() {
			c.Session.CookieName = "__Host-zt_session"
		} else {
			c.Session.CookieName = "zt_session"
		}
	}
	if c.Passkeys.RPID == "" {
		c.Passkeys.RPID = c.PublicURL.Hostname()
	}
	if c.JWT.Audience == "" {
		c.JWT.Audience = c.UpstreamURL.String()
	}
}

func (c *Config) validate() error {
	var errs []error
	if c.Session.Store != "memory" && c.Session.Store != "redis" {
		errs = append(errs, fmt.Errorf("ZT_SESSION_STORE must be memory or redis, got %q", c.Session.Store))
	}
	if c.Session.Store == "redis" && c.Session.RedisURL == "" {
		errs = append(errs, errors.New("ZT_REDIS_URL is required when ZT_SESSION_STORE=redis"))
	}
	if c.JWT.TTL <= 0 || c.JWT.TTL > 10*time.Minute {
		errs = append(errs, fmt.Errorf("ZT_JWT_TTL must be in (0, 10m], got %s", c.JWT.TTL))
	}
	if c.JWT.RotationInterval < time.Minute {
		errs = append(errs, fmt.Errorf("ZT_JWT_ROTATION_INTERVAL must be at least 1m, got %s", c.JWT.RotationInterval))
	}
	if c.Session.TTL <= 0 || c.Session.IdleTimeout <= 0 {
		errs = append(errs, errors.New("session TTL and idle timeout must be positive"))
	}
	if !hasScope(c.OIDC.Scopes, "openid") {
		errs = append(errs, errors.New("ZT_OIDC_SCOPES must include openid"))
	}
	if c.PublicURL.Path != "" && c.PublicURL.Path != "/" {
		errs = append(errs, errors.New("ZT_PUBLIC_URL must not contain a path"))
	}
	return errors.Join(errs...)
}

func hasScope(scopes []string, s string) bool {
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

type env struct {
	get  func(string) string
	errs []error
}

func (e *env) str(k, def string) string {
	if v := strings.TrimSpace(e.get(k)); v != "" {
		return v
	}
	return def
}

func (e *env) required(k string) string {
	v := strings.TrimSpace(e.get(k))
	if v == "" {
		e.errs = append(e.errs, fmt.Errorf("%s is required", k))
	}
	return v
}

func (e *env) url(k string, required bool) *url.URL {
	raw := e.str(k, "")
	if raw == "" {
		if required {
			e.errs = append(e.errs, fmt.Errorf("%s is required", k))
		}
		return &url.URL{}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		e.errs = append(e.errs, fmt.Errorf("%s must be an absolute http(s) URL, got %q", k, raw))
		return &url.URL{}
	}
	return u
}

func (e *env) duration(k string, def time.Duration) time.Duration {
	raw := e.str(k, "")
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", k, err))
		return def
	}
	return d
}

func (e *env) bool(k string, def bool) bool {
	raw := e.str(k, "")
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", k, err))
		return def
	}
	return b
}

func (e *env) list(k string, def []string) []string {
	raw := e.str(k, "")
	if raw == "" {
		return def
	}
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, f)
	}
	return out
}

func (e *env) level(k string, def slog.Level) slog.Level {
	raw := e.str(k, "")
	if raw == "" {
		return def
	}
	var l slog.Level
	if err := l.UnmarshalText([]byte(raw)); err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", k, err))
		return def
	}
	return l
}

func (e *env) secret(k string) []byte {
	raw := e.required(k)
	if raw == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		b, err = base64.RawURLEncoding.DecodeString(raw)
	}
	if err != nil || len(b) != 32 {
		e.errs = append(e.errs, fmt.Errorf("%s must be 32 bytes, base64 encoded (openssl rand -base64 32)", k))
		return nil
	}
	return b
}
