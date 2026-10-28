// Command gateway runs the zero-trust reverse proxy.
//
// Configuration is entirely by environment variable; see the README or
// .env.example. Validate without starting:
//
//	gateway -check
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/MahyarNemati/zero-trust-gateway/internal/audit"
	"github.com/MahyarNemati/zero-trust-gateway/internal/config"
	"github.com/MahyarNemati/zero-trust-gateway/internal/gateway"
	"github.com/MahyarNemati/zero-trust-gateway/internal/metrics"
	"github.com/MahyarNemati/zero-trust-gateway/internal/oidcauth"
	"github.com/MahyarNemati/zero-trust-gateway/internal/passkey"
	"github.com/MahyarNemati/zero-trust-gateway/internal/policy"
	"github.com/MahyarNemati/zero-trust-gateway/internal/session"
	"github.com/MahyarNemati/zero-trust-gateway/internal/token"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	check := false
	showVersion := false
	for _, a := range os.Args[1:] {
		switch a {
		case "-check", "--check":
			check = true
		case "-version", "--version":
			showVersion = true
		case "-h", "-help", "--help":
			fmt.Fprint(os.Stderr, usage)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q\n\n%s", a, usage)
			os.Exit(2)
		}
	}
	if showVersion {
		fmt.Println("gateway", version)
		return
	}

	if err := run(check); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

const usage = `usage: gateway [-check] [-version]

The gateway is configured entirely by environment variable. Required:

  ZT_PUBLIC_URL        external URL of the gateway, e.g. https://app.example.com
  ZT_UPSTREAM_URL      where allowed requests are forwarded
  ZT_POLICY_FILE       path to the YAML policy
  ZT_SESSION_SECRET    32+ bytes, base64 or hex; seals the session cookie
  ZT_OIDC_ISSUER       OIDC issuer URL
  ZT_OIDC_CLIENT_ID    OIDC client id

See the README for the full list.
`

func run(checkOnly bool) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	// Load the policy before anything else binds a port: a syntax error should
	// be a startup failure, not a 500 on the first request.
	policies, err := policy.NewStore(cfg.PolicyFile, log, nil)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	if checkOnly {
		fmt.Printf("configuration OK: upstream %s, policy %s (%d routes)\n",
			cfg.UpstreamURL, cfg.PolicyFile, policies.Engine().Routes())
		return nil
	}

	m := metrics.New()

	sealer, err := session.NewSealer(cfg.Session.Secret)
	if err != nil {
		return fmt.Errorf("session sealer: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sessionStore, passkeyStore, closeStores, err := openStores(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStores()

	sessions := &session.Manager{
		Store:       sessionStore,
		Sealer:      sealer,
		CookieName:  cfg.Session.CookieName,
		Secure:      cfg.Secure(),
		TTL:         cfg.Session.TTL,
		IdleTimeout: cfg.Session.IdleTimeout,
	}

	keyring, err := newKeyring(cfg)
	if err != nil {
		return err
	}

	issuer := &token.Issuer{
		Keys:     keyring,
		Issuer:   cfg.PublicURL.String(),
		Audience: cfg.JWT.Audience,
		TTL:      cfg.JWT.TTL,
	}

	oidcClient := oidcauth.New(oidcauth.Config{
		Issuer:       cfg.OIDC.Issuer,
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL:  cfg.PublicURL.JoinPath(gateway.Prefix, "callback").String(),
		Scopes:       cfg.OIDC.Scopes,
		GroupsClaim:  cfg.OIDC.GroupsClaim,
	})

	var passkeys *passkey.Service
	if cfg.Passkeys.Enabled {
		passkeys, err = passkey.New(passkey.Config{
			RPID:          cfg.Passkeys.RPID,
			RPDisplayName: cfg.Passkeys.RPDisplayName,
			Origins:       []string{cfg.PublicURL.Scheme + "://" + cfg.PublicURL.Host},
		}, passkeyStore)
		if err != nil {
			return fmt.Errorf("passkeys: %w", err)
		}
	}

	gw, err := gateway.New(gateway.Deps{
		Config:   cfg,
		Policy:   policies,
		Sessions: sessions,
		Sealer:   sealer,
		OIDC:     oidcClient,
		Passkeys: passkeys,
		Tokens:   issuer,
		Keys:     keyring,
		Metrics:  m,
		Audit:    audit.New(os.Stdout),
		Log:      log,
	})
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	// Policy hot reload. A bad file leaves the previous policy in place, so an
	// editing mistake degrades to "your change did not apply".
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := policies.Watch(ctx, 250*time.Millisecond); err != nil && ctx.Err() == nil {
			log.Error("policy watcher stopped", "err", err)
		}
	}()

	// Upstream signing key rotation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		keyring.Run(ctx, log)
	}()

	proxySrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// The metrics listener is separate so /metrics is never reachable through
	// the public listener, where it would sit in front of the upstream.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", m.Handler())
	metricsSrv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serve := func(name string, srv *http.Server) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("listening", "server", name, "addr", srv.Addr, "version", version)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	serve("proxy", proxySrv)
	if cfg.MetricsAddr != "" {
		serve("metrics", metricsSrv)
	}

	log.Info("gateway started",
		"upstream", cfg.UpstreamURL.String(),
		"public_url", cfg.PublicURL.String(),
		"routes", policies.Engine().Routes(),
		"passkeys", cfg.Passkeys.Enabled,
		"session_store", cfg.Session.Store,
	)

	select {
	case err := <-errc:
		stop()
		shutdown(proxySrv, metricsSrv, log)
		wg.Wait()
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdown(proxySrv, metricsSrv, log)
	wg.Wait()
	log.Info("stopped")
	return nil
}

func shutdown(proxySrv, metricsSrv *http.Server, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for name, srv := range map[string]*http.Server{"proxy": proxySrv, "metrics": metricsSrv} {
		if err := srv.Shutdown(ctx); err != nil {
			log.Warn("shutdown", "server", name, "err", err)
		}
	}
}

// openStores builds the session and passkey stores, returning a closer.
func openStores(ctx context.Context, cfg *config.Config) (session.Store, passkey.Store, func(), error) {
	switch cfg.Session.Store {
	case "memory":
		// Sessions live in this process only, so a restart signs everyone out
		// and two replicas do not share sessions. Fine for development.
		return session.NewMemoryStore(), passkey.NewMemoryStore(), func() {}, nil

	case "redis":
		opts, err := redis.ParseURL(cfg.Session.RedisURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ZT_REDIS_URL: %w", err)
		}
		rdb := redis.NewClient(opts)

		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := rdb.Ping(pingCtx).Err(); err != nil {
			_ = rdb.Close()
			return nil, nil, nil, fmt.Errorf("redis unreachable: %w", err)
		}
		return session.NewRedisStore(rdb, "zt:sess:"),
			passkey.NewRedisStore(rdb, "zt:pk:"),
			func() { _ = rdb.Close() },
			nil

	default:
		return nil, nil, nil, fmt.Errorf("ZT_SESSION_STORE must be memory or redis, got %q", cfg.Session.Store)
	}
}

// newKeyring returns a static keyring when a key file is configured, and a
// rotating one otherwise.
func newKeyring(cfg *config.Config) (*token.Keyring, error) {
	if cfg.JWT.SigningKeyFile != "" {
		k, err := token.NewStaticKeyring(cfg.JWT.SigningKeyFile)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		return k, nil
	}
	// Retain previous keys for two rotations so assertions minted just before
	// a rotation still verify against the published JWKS.
	k, err := token.NewRotatingKeyring(cfg.JWT.RotationInterval, 2*cfg.JWT.RotationInterval)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return k, nil
}
