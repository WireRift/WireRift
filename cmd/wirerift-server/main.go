package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
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

// normalizeArgs converts --flag to -flag and reorders so flags come before positional args.
func normalizeArgs(args []string) []string {
	var flags []string
	var positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "--") && !strings.HasPrefix(a, "---") && a != "--" {
			a = a[1:]
		}
		if strings.HasPrefix(a, "-") && a != "-" && a != "--" {
			flags = append(flags, a)
			// "-flag=value" carries its own value and must not swallow the next arg.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				isBool := a == "-v" || a == "-json" || a == "-auto-cert" || a == "-acme-staging" || a == "-version" || a == "-dev"
				if !isBool {
					i++
					flags = append(flags, args[i])
				}
			}
		} else if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		} else {
			positional = append(positional, a)
		}
		i++
	}
	return append(flags, positional...)
}

func run(parentCtx context.Context, args []string) error {
	// "wirerift-server ca ..." manages the local development CA.
	if len(args) > 0 && args[0] == "ca" {
		return runCA(args[1:], os.Stdout, tlspkg.DefaultTrust())
	}
	// "wirerift-server doctor" checks that this machine can run the server.
	if len(args) > 0 && args[0] == "doctor" {
		return runServerDoctor(args[1:], os.Stdout)
	}

	// Parse flags
	fs := flag.NewFlagSet("wirerift-server", flag.ContinueOnError)

	// Server options
	controlAddr := fs.String("control", ":4443", "Control plane address")
	httpAddr := fs.String("http", ":80", "HTTP edge address")
	httpsAddr := fs.String("https", ":443", "HTTPS edge address")
	dashboardAddr := fs.Int("dashboard-port", 4040, "Dashboard port")
	dashboardBind := fs.String("dashboard-bind", "127.0.0.1", "Dashboard bind address (use 0.0.0.0 to expose; the dashboard is plain HTTP)")
	domain := fs.String("domain", "wirerift.com", "Base domain for tunnels")
	tcpPortRange := fs.String("tcp-ports", "20000-29999", "TCP tunnel port range")

	// Local development mode
	devMode := fs.Bool("dev", false, "Local development: trusted HTTPS for *.localhost via a local CA (see 'wirerift-server ca trust')")
	caDirFlag := fs.String("ca-dir", "", "Local CA directory for -dev (default: per-user config dir)")

	// TLS options
	autoCert := fs.Bool("auto-cert", false, "Auto-generate self-signed certificates")
	certDir := fs.String("cert-dir", "certs", "Directory for certificates")
	acmeEmail := fs.String("acme-email", "", "Email for Let's Encrypt (enables ACME)")
	dashCert := fs.String("dashboard-tls-cert", "", "TLS certificate (PEM) for the dashboard; with -dashboard-tls-key serves it over HTTPS")
	dashKey := fs.String("dashboard-tls-key", "", "TLS private key (PEM) for the dashboard")
	controlCert := fs.String("control-tls-cert", "", "TLS certificate (PEM) for the control plane; with -control-tls-key enables TLS on :4443")
	controlKey := fs.String("control-tls-key", "", "TLS private key (PEM) for the control plane")
	acmeStaging := fs.Bool("acme-staging", false, "Use Let's Encrypt staging server")

	// Custom domains
	dnsServer := fs.String("dns-server", "", "DNS server (host[:port]) used to verify custom-domain TXT records (default: system resolver)")

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
  wirerift-server doctor [options]                   # Check ports, certificates, DNS (nothing is started)
  wirerift-server ca trust                           # Local HTTPS for -dev

Environment Variables:
  WIRERIFT_DOMAIN       Base domain (default: wirerift.com)
  WIRERIFT_CONTROL_ADDR Control plane address
  WIRERIFT_HTTP_ADDR    HTTP edge address

`)
	}

	if err := fs.Parse(normalizeArgs(args)); err != nil {
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

	// Get config from environment. A flag given on the command line always wins,
	// even when its value equals the default.
	given := visitedFlags(fs)
	if envDomain := os.Getenv("WIRERIFT_DOMAIN"); envDomain != "" && !given["domain"] {
		*domain = envDomain
	}
	if envControl := os.Getenv("WIRERIFT_CONTROL_ADDR"); envControl != "" && !given["control"] {
		*controlAddr = envControl
	}
	if envHTTP := os.Getenv("WIRERIFT_HTTP_ADDR"); envHTTP != "" && !given["http"] {
		*httpAddr = envHTTP
	}

	// -dev: loopback + unprivileged ports, trusted HTTPS from the local CA
	var dev *devSetup
	if *devMode {
		var err error
		dev, err = setupDev(devOptions{
			Domain: domain, Control: controlAddr, HTTP: httpAddr, HTTPS: httpsAddr,
			Explicit: explicitSettings(visitedFlags(fs)), CADir: *caDirFlag, ACMEEmail: *acmeEmail,
		})
		if err != nil {
			return err
		}
	}

	// Create auth manager (flag > env > random)
	authMgr := auth.NewManager(*tokenFlag)
	devToken := authMgr.DevToken()

	// Print connection info prominently
	tokenSource := tokenSourceLabel(*tokenFlag)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════╗")
	fmt.Fprintln(os.Stderr, "║              WireRift Server                 ║")
	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════╣")
	fmt.Fprintf(os.Stderr, "  Control:   %s\n", *controlAddr)
	fmt.Fprintf(os.Stderr, "  HTTP:      %s\n", *httpAddr)
	dashScheme := "http"
	if *dashCert != "" {
		dashScheme = "https"
	}
	fmt.Fprintf(os.Stderr, "  Dashboard: %s://localhost:%d\n", dashScheme, *dashboardAddr)
	fmt.Fprintf(os.Stderr, "  Domain:    %s\n", *domain)
	dev.printBanner(os.Stderr, *httpsAddr, *domain)
	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════╣")
	shownToken := printToken(os.Stderr, tokenSource, devToken)
	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════╣")
	fmt.Fprintln(os.Stderr, "  Quick start:")
	serverAddr := *controlAddr
	if strings.HasPrefix(serverAddr, ":") {
		serverAddr = "localhost" + serverAddr
	}
	if *controlCert != "" {
		serverAddr = "tls://" + serverAddr
	}
	fmt.Fprintf(os.Stderr, "  wirerift http 8080 -server %s -token %s\n", serverAddr, shownToken)
	fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════╝")

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

	if err := checkCertPair("dashboard-tls", *dashCert, *dashKey); err != nil {
		return err
	}
	controlTLS, err := loadControlTLS(*controlCert, *controlKey)
	if err != nil {
		return err
	}
	srvConfig.ControlTLSConfig = controlTLS
	if tlsMgr != nil {
		srvConfig.TLSConfig = tlsMgr.TLSConfig()
		srvConfig.ACMEChallengeHandler = tlsMgr.ACMEChallengeHandler()
	}
	if dev != nil {
		srvConfig.TLSConfig = dev.Provider.TLSConfig()
		srvConfig.PublicScheme = "https"
		srvConfig.PublicPort = dev.Port
		srvConfig.TCPBindHost = "127.0.0.1" // -dev must not expose anything to the network
	} else if err := configureCustomDomains(&srvConfig, tlsMgr, *certDir, *dnsServer, *httpsAddr); err != nil {
		return err
	}

	// Create server
	srv := server.New(srvConfig, logger)
	if tlsMgr != nil {
		// Certificates only for names a live tunnel serves (subdomains and
		// verified custom domains), so random SNI cannot trigger issuance.
		tlsMgr.SetHostAllower(srv.IsHostServed)
	}

	// Create dashboard
	dash := dashboard.New(dashboard.Config{
		Server:       srv,
		AuthManager:  authMgr,
		Port:         *dashboardAddr,
		HTTPSEnabled: tlsMgr != nil,
	})

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	startCertRenewal(ctx, tlsMgr)

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
		Addr:              net.JoinHostPort(*dashboardBind, strconv.Itoa(*dashboardAddr)),
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
		var err error
		if *dashCert != "" {
			err = dashServer.ListenAndServeTLS(*dashCert, *dashKey)
		} else {
			err = dashServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("dashboard error", "error", err)
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	// Shutdown dashboard with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = dashServer.Shutdown(shutdownCtx)

	// Stop server (Stop always returns nil)
	_ = srv.Stop()

	logger.Info("server stopped")
	return nil
}

// checkCertPair requires -<name>-cert and -<name>-key to be set together.
func checkCertPair(name, cert, key string) error {
	if (cert == "") != (key == "") {
		return fmt.Errorf("-%s-cert and -%s-key must be set together", name, name)
	}
	return nil
}

// loadControlTLS builds the control-plane TLS config (nil when not requested).
func loadControlTLS(cert, key string) (*tls.Config, error) {
	if err := checkCertPair("control-tls", cert, key); err != nil {
		return nil, err
	}
	if cert == "" {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("load control-plane TLS key pair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

// httpsPort extracts the port of an address like ":443"; the standard port
// (and anything unparsable) yields 0, meaning "omit the port from URLs".
func httpsPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n == 443 {
		return 0
	}
	return n
}

// txtResolverFor returns a TXT resolver that asks the given DNS server
// (host or host:port, default port 53). An empty address means the system
// resolver (nil).
func txtResolverFor(addr string) (server.TXTResolver, error) {
	if addr == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "53")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid -dns-server %q (want host or host:port)", addr)
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	return r.LookupTXT, nil
}

// configureCustomDomains prepares everything custom domains need on a regular
// (non-dev) server: the persisted proof secret, the DNS resolver for the TXT
// check, and https URLs when trusted (ACME) certificates are available.
// startCertRenewal renews certificates in the background until ctx ends.
func startCertRenewal(ctx context.Context, tlsMgr *tlspkg.Manager) {
	if tlsMgr != nil {
		tlsMgr.StartRenewal(ctx, tlspkg.RenewalCheckInterval)
	}
}

func configureCustomDomains(cfg *server.Config, tlsMgr *tlspkg.Manager, certDir, dnsServer, httpsAddr string) error {
	secret, err := loadOrCreateDomainSecret(certDir)
	if err != nil {
		return err
	}
	cfg.DomainSecret = secret

	resolver, err := txtResolverFor(dnsServer)
	if err != nil {
		return err
	}
	cfg.TXTResolver = resolver

	if tlsMgr != nil && tlsMgr.IsACMEEnabled() {
		cfg.PublicScheme = "https"
		cfg.PublicPort = httpsPort(httpsAddr)
	}
	return nil
}

// tokenSourceLabel says where the auth token came from.
func tokenSourceLabel(tokenFlag string) string {
	switch {
	case tokenFlag != "":
		return "-token flag"
	case os.Getenv("WIRERIFT_TOKEN") != "":
		return "WIRERIFT_TOKEN env" //nolint:gosec // a label, not a credential
	}
	return "random"
}

// printToken prints the token lines of the banner and returns the token to
// show in the quick-start command. Only an auto-generated token is printed (it
// cannot be known otherwise); a token the operator supplied must not land in logs.
func printToken(w io.Writer, source, token string) string {
	fmt.Fprintf(w, "  Token (%s):\n", source)
	if source == "random" {
		fmt.Fprintf(w, "  %s\n", token)
		return token
	}
	fmt.Fprintln(w, "  (hidden: supplied by you)")
	return "<your token>"
}
