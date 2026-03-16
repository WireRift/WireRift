package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/config"
	"github.com/wirerift/wirerift/internal/dashboard"
	"github.com/wirerift/wirerift/internal/server"
	tlspkg "github.com/wirerift/wirerift/internal/tls"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(parentCtx context.Context, args []string) error {
	// Parse flags
	fs := flag.NewFlagSet("wirerift-server", flag.ContinueOnError)

	// Server options
	controlAddr := fs.String("control", ":4443", "Control plane address")
	httpAddr := fs.String("http", ":80", "HTTP edge address")
	httpsAddr := fs.String("https", ":443", "HTTPS edge address")
	dashboardAddr := fs.Int("dashboard-port", 4040, "Dashboard port")
	domain := fs.String("domain", "wirerift.com", "Base domain for tunnels")
	tcpPortRange := fs.String("tcp-ports", "20000-29999", "TCP tunnel port range")

	// TLS options
	autoCert := fs.Bool("auto-cert", false, "Auto-generate self-signed certificates")
	certDir := fs.String("cert-dir", "certs", "Directory for certificates")
	acmeEmail := fs.String("acme-email", "", "Email for Let's Encrypt (enables ACME)")
	acmeStaging := fs.Bool("acme-staging", false, "Use Let's Encrypt staging server")

	// Auth
	tokenFlag := fs.String("token", "", "Set a fixed auth token (default: auto-generated)")

	// Logging
	verbose := fs.Bool("v", false, "Verbose logging")
	jsonLog := fs.Bool("json", false, "JSON log format")

	// Version
	showVersion := fs.Bool("version", false, "Show version")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `WireRift Server - Tunnel Server

Usage:
  wirerift-server [options]

Options:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  wirerift-server                                    # Start with defaults
  wirerift-server -domain mytunnel.com               # Custom domain
  wirerift-server -auto-cert -cert-dir ./certs       # Auto-generate certificates
  wirerift-server -control :8443 -http :8080         # Custom ports

Environment Variables:
  WIRERIFT_DOMAIN       Base domain (default: wirerift.com)
  WIRERIFT_CONTROL_ADDR Control plane address
  WIRERIFT_HTTP_ADDR    HTTP edge address

`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Printf("WireRift Server %s (commit: %s, built: %s)\n", version, commit, date)
		return nil
	}

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	var logger *slog.Logger
	if *jsonLog {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	}

	// Get config from environment
	if envDomain := os.Getenv("WIRERIFT_DOMAIN"); envDomain != "" && *domain == "wirerift.com" {
		*domain = envDomain
	}
	if envControl := os.Getenv("WIRERIFT_CONTROL_ADDR"); envControl != "" && *controlAddr == ":4443" {
		*controlAddr = envControl
	}
	if envHTTP := os.Getenv("WIRERIFT_HTTP_ADDR"); envHTTP != "" && *httpAddr == ":80" {
		*httpAddr = envHTTP
	}

	// Create auth manager (flag > env > random)
	authMgr := auth.NewManager(*tokenFlag)
	devToken := authMgr.DevToken()

	// Print token prominently so it's easy to copy
	tokenSource := "generated (random)"
	if *tokenFlag != "" {
		tokenSource = "from -token flag"
	} else if os.Getenv("WIRERIFT_TOKEN") != "" {
		tokenSource = "from WIRERIFT_TOKEN env"
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "========================================")
	fmt.Fprintf(os.Stderr, "  Development Token (%s):\n", tokenSource)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s\n", devToken)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Export: export WIRERIFT_TOKEN=%s\n", devToken)
	fmt.Fprintln(os.Stderr, "========================================")

	// Create domain manager
	domainMgr := config.NewDomainManager(*domain)

	// Create TLS manager
	var tlsMgr *tlspkg.Manager
	var tlsErr error
	if *autoCert || *acmeEmail != "" {
		tlsMgr, tlsErr = tlspkg.NewManager(tlspkg.Config{
			Domain:     *domain,
			CertDir:    *certDir,
			AutoCert:   true,
			Email:      *acmeEmail,
			UseStaging: *acmeStaging,
		})
		if tlsErr != nil {
			return fmt.Errorf("failed to create TLS manager: %v", tlsErr)
		}
		if tlsMgr.IsACMEEnabled() {
			logger.Info("Let's Encrypt ACME enabled", "email", *acmeEmail, "staging", *acmeStaging)
		}
	}

	// Create server config
	srvConfig := server.DefaultConfig()
	srvConfig.Domain = *domain
	srvConfig.ControlAddr = *controlAddr
	srvConfig.HTTPAddr = *httpAddr
	srvConfig.HTTPSAddr = *httpsAddr
	srvConfig.TCPAddrRange = *tcpPortRange
	srvConfig.AuthManager = authMgr

	if tlsMgr != nil {
		srvConfig.TLSConfig = tlsMgr.TLSConfig()
		srvConfig.ACMEChallengeHandler = tlsMgr.ACMEChallengeHandler()
	}

	// Create server
	srv := server.New(srvConfig, logger)

	// Create dashboard
	dash := dashboard.New(dashboard.Config{
		Server:       srv,
		AuthManager:  authMgr,
		DomainMgr:    domainMgr,
		Port:         *dashboardAddr,
		HTTPSEnabled: tlsMgr != nil,
	})

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("shutting down", "signal", sig)
		cancel()
	}()

	// Start server
	logger.Info("starting WireRift server",
		"version", version,
		"domain", *domain,
		"control", *controlAddr,
		"http", *httpAddr,
		"dashboard_port", *dashboardAddr,
	)

	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	// Start dashboard
	dashServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", *dashboardAddr),
		Handler:           dash.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("dashboard panic", "error", r)
			}
		}()
		logger.Info("dashboard started", "addr", dashServer.Addr)
		if err := dashServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("dashboard error", "error", err)
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	// Shutdown dashboard with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	dashServer.Shutdown(shutdownCtx)

	// Stop server (Stop always returns nil)
	srv.Stop()

	logger.Info("server stopped")
	return nil
}
