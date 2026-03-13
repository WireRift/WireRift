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
	// Parse flags
	fs := flag.NewFlagSet("wirerift-server", flag.ExitOnError)

	// Server options
	controlAddr := fs.String("control", ":4443", "Control plane address")
	httpAddr := fs.String("http", ":80", "HTTP edge address")
	httpsAddr := fs.String("https", ":443", "HTTPS edge address")
	dashboardAddr := fs.Int("dashboard-port", 4040, "Dashboard port")
	domain := fs.String("domain", "wirerift.dev", "Base domain for tunnels")
	tcpPortRange := fs.String("tcp-ports", "20000-29999", "TCP tunnel port range")

	// TLS options
	autoCert := fs.Bool("auto-cert", false, "Auto-generate self-signed certificates")
	certDir := fs.String("cert-dir", "certs", "Directory for certificates")

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
  WIRERIFT_DOMAIN       Base domain (default: wirerift.dev)
  WIRERIFT_CONTROL_ADDR Control plane address
  WIRERIFT_HTTP_ADDR    HTTP edge address

`)
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("WireRift Server %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
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
	if envDomain := os.Getenv("WIRERIFT_DOMAIN"); envDomain != "" && *domain == "wirerift.dev" {
		*domain = envDomain
	}
	if envControl := os.Getenv("WIRERIFT_CONTROL_ADDR"); envControl != "" && *controlAddr == ":4443" {
		*controlAddr = envControl
	}
	if envHTTP := os.Getenv("WIRERIFT_HTTP_ADDR"); envHTTP != "" && *httpAddr == ":80" {
		*httpAddr = envHTTP
	}

	// Create auth manager
	authMgr := auth.NewManager()

	// Create domain manager
	domainMgr := config.NewDomainManager(*domain)

	// Create TLS manager
	var tlsMgr *tlspkg.Manager
	var tlsErr error
	if *autoCert {
		tlsMgr, tlsErr = tlspkg.NewManager(tlspkg.Config{
			Domain:   *domain,
			CertDir:  *certDir,
			AutoCert: true,
		})
		if tlsErr != nil {
			logger.Error("failed to create TLS manager", "error", tlsErr)
			os.Exit(1)
		}
	}

	// Create server config
	srvConfig := server.DefaultConfig()
	srvConfig.Domain = *domain
	srvConfig.ControlAddr = *controlAddr
	srvConfig.HTTPAddr = *httpAddr
	srvConfig.HTTPSAddr = *httpsAddr
	srvConfig.TCPAddrRange = *tcpPortRange

	if tlsMgr != nil {
		srvConfig.TLSConfig = tlsMgr.TLSConfig()
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
	ctx, cancel := context.WithCancel(context.Background())
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
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	// Start dashboard
	dashServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *dashboardAddr),
		Handler: dash.Handler(),
	}

	go func() {
		logger.Info("dashboard started", "addr", dashServer.Addr)
		if err := dashServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("dashboard error", "error", err)
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	// Shutdown dashboard
	if err := dashServer.Shutdown(ctx); err != nil {
		logger.Warn("dashboard shutdown error", "error", err)
	}

	// Stop server
	if err := srv.Stop(); err != nil {
		logger.Warn("server shutdown error", "error", err)
	}

	logger.Info("server stopped")
}
