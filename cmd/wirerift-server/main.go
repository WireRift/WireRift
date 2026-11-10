package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

// runSubcommand runs "ca", "token" or "doctor" when args name one, and reports
// whether it did.
func runSubcommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "ca": // manages the local development CA
		return true, runCA(args[1:], os.Stdout, tlspkg.DefaultTrust())
	case "token": // manages access tokens
		return true, runToken(args[1:], os.Stdout)
	case "doctor": // checks that this machine can run the server
		return true, runServerDoctor(args[1:], os.Stdout)
	}
	return false, nil
}

func run(parentCtx context.Context, args []string) error {
	if handled, err := runSubcommand(args); handled {
		return err
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
	offlineGrace := fs.Duration("offline-grace", 2*time.Minute, "keep a dropped client's subdomains reserved for it this long, showing visitors 503 (0 = release at once)")
	dashHost := fs.String("dashboard-host", "", "also serve the dashboard over the HTTPS edge on this host: a label (\"dashboard\" -> dashboard.<domain>) or a full name; sign-in with a token is always required")
	dashAllow := fs.String("dashboard-allow", "", "comma-separated addresses or CIDR ranges allowed to reach the dashboard (default: anyone; sign-in is always required). Local access through an SSH tunnel stays possible")
	edgeRate := fs.Float64("edge-rate", 0, "requests per second one visitor IP may send to the HTTP edge (0 = default 100)")
	edgeBurst := fs.Int("edge-burst", 0, "burst allowance on top of -edge-rate (0 = default 50)")
	tcpIdle := fs.Duration("tcp-idle-timeout", 0, "close a TCP tunnel connection that moved no data for this long (0 = never)")
	halfClose := fs.Duration("half-close-timeout", 0, "reset a stream the server closed once the client sends nothing for this long (0 = never)")

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
	trustedProxyCIDRs := fs.String("trusted-proxy-cidrs", "", "Comma-separated proxy CIDRs trusted to supply X-Forwarded-For (default: none)")

	// Auth
	tokenFlag := fs.String("token", "", "Set a fixed auth token (default: auto-generated)")
	tokensFile := fs.String("tokens-file", "", "Token file made with 'wirerift-server token create' (default: <cert-dir>/tokens.json)")

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

	authMgr, tokenSource, err := setupAuth(*tokenFlag, tokenFilePath(*tokensFile, *certDir), logger)
	if err != nil {
		return err
	}
	devToken := authMgr.DevToken()

	// Create TLS manager before printing connection instructions: when ACME is
	// active it also secures the public control plane.
	tlsMgr, err := newTLSManager(*autoCert, *acmeEmail, *domain, *certDir, *acmeStaging, logger)
	if err != nil {
		return err
	}

	// Print connection info prominently
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
	if *controlCert != "" || (tlsMgr != nil && tlsMgr.IsACMEEnabled()) {
		serverAddr = "tls://" + serverAddr
	}
	fmt.Fprintf(os.Stderr, "  wirerift http 8080 -server %s -token %s\n", serverAddr, shownToken)
	fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════╝")

	// Create server config
	srvConfig := server.DefaultConfig()
	srvConfig.Domain = *domain
	srvConfig.ControlAddr = *controlAddr
	srvConfig.HTTPAddr = *httpAddr
	srvConfig.HTTPSAddr = *httpsAddr
	srvConfig.TCPAddrRange = *tcpPortRange
	srvConfig.HalfCloseTimeout = *halfClose
	srvConfig.TCPIdleTimeout = *tcpIdle
	if err := setEdgeRate(&srvConfig, *edgeRate, *edgeBurst); err != nil {
		return err
	}
	srvConfig.OfflineGrace = *offlineGrace
	srvConfig.HeldFile = filepath.Join(*certDir, "held.json")
	srvConfig.StateFile = filepath.Join(*certDir, "state.json")
	srvConfig.AuthManager = authMgr
	srvConfig.Version = version
	srvConfig.TrustedProxyCIDRs = splitCommaList(*trustedProxyCIDRs)

	dashboardTLS, err := loadDashboardTLS(*dashCert, *dashKey)
	if err != nil {
		return err
	}
	controlTLS, err := configuredControlTLS(*controlCert, *controlKey, tlsMgr)
	if err != nil {
		return err
	}
	srvConfig.ControlTLSConfig = controlTLS
	applyTLSManager(&srvConfig, tlsMgr)
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
		Certs:        certProvider(tlsMgr),
		TokenFile:    tokenFilePath(*tokensFile, *certDir),
		Allow:        splitCommaList(*dashAllow),
		// A token created or revoked in the Admin tab applies at once.
		OnTokensChanged: func() { reloadTokens(authMgr, srv, tokenFilePath(*tokensFile, *certDir), logger) },
	})
	if err := publishDashboard(srv, dash, *dashHost, *domain, *dashAllow, tlsMgr != nil || dev != nil, logger); err != nil {
		return err
	}
	dashServer := &http.Server{
		Addr:              net.JoinHostPort(*dashboardBind, strconv.Itoa(*dashboardAddr)),
		Handler:           dash.Handler(),
		TLSConfig:         dashboardTLS,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	dashListener, err := net.Listen("tcp", dashServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to start dashboard on %s: %w", dashServer.Addr, err)
	}
	defer dashListener.Close()

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	startCertRenewal(ctx, tlsMgr)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("shutting down", "signal", sig)
			cancel()
		case <-ctx.Done():
		}
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

	go watchTokenFile(ctx, authMgr, srv, tokenFilePath(*tokensFile, *certDir), tokenReloadInterval, logger)

	// Start dashboard on the listener reserved before the other services were
	// started, so a bind failure cannot leave a partially running process.
	dashboardErrors := make(chan error, 1)
	go func() {
		logger.Info("dashboard started", "addr", dashServer.Addr)
		if err := serveDashboard(dashServer, dashListener, dashboardTLS != nil); err != nil {
			select {
			case dashboardErrors <- err:
			default:
			}
		}
	}()

	// Wait for operator shutdown or any required serving component to fail.
	runErr := awaitRuntimeEnd(ctx, cancel, srv.Errors(), dashboardErrors)

	// Shutdown dashboard with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = dashServer.Shutdown(shutdownCtx)

	// Stop server (Stop always returns nil)
	_ = srv.Stop()

	logger.Info("server stopped")
	return runErr
}

func awaitRuntimeEnd(ctx context.Context, cancel context.CancelFunc, serverErrors, dashboardErrors <-chan error) error {
	select {
	case <-ctx.Done():
		// reportFatalListenerError sends before cancelling the server context.
		// Prefer that concrete failure over a generic context cancellation.
		select {
		case err := <-serverErrors:
			return fmt.Errorf("server runtime failure: %w", err)
		default:
			return nil
		}
	case err := <-serverErrors:
		cancel()
		return fmt.Errorf("server runtime failure: %w", err)
	case err := <-dashboardErrors:
		cancel()
		return fmt.Errorf("dashboard runtime failure: %w", err)
	}
}

func serveDashboard(server *http.Server, listener net.Listener, useTLS bool) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("dashboard panic: %v", recovered)
		}
	}()
	if useTLS {
		err = server.ServeTLS(listener, "", "")
	} else {
		err = server.Serve(listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("dashboard stopped unexpectedly")
	}
	return err
}

func newTLSManager(autoCert bool, email, domain, certDir string, staging bool, logger *slog.Logger) (*tlspkg.Manager, error) {
	if !autoCert && email == "" {
		return nil, nil
	}
	mgr, err := tlspkg.NewManager(tlspkg.Config{
		Domain:      domain,
		CertDir:     certDir,
		AutoCert:    true,
		Email:       email,
		UseStaging:  staging,
		RequireACME: email != "",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS manager: %v", err)
	}
	if mgr.IsACMEEnabled() {
		logger.Info("Let's Encrypt ACME enabled", "email", email, "staging", staging)
	}
	return mgr, nil
}

// checkCertPair requires -<name>-cert and -<name>-key to be set together.
func checkCertPair(name, cert, key string) error {
	if (cert == "") != (key == "") {
		return fmt.Errorf("-%s-cert and -%s-key must be set together", name, name)
	}
	return nil
}

func loadDashboardTLS(cert, key string) (*tls.Config, error) {
	if err := checkCertPair("dashboard-tls", cert, key); err != nil {
		return nil, err
	}
	if cert == "" {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("load dashboard TLS key pair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}, nil
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

func configuredControlTLS(cert, key string, mgr *tlspkg.Manager) (*tls.Config, error) {
	config, err := loadControlTLS(cert, key)
	if err != nil {
		return nil, err
	}
	if config == nil && mgr != nil && mgr.IsACMEEnabled() {
		config = mgr.TLSConfig()
	}
	return config, nil
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

func splitCommaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
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
// loadTokenFile loads the token file into mgr and logs how many tokens it holds.
func loadTokenFile(mgr *auth.Manager, path string, logger *slog.Logger) error {
	n, err := mgr.LoadTokenFile(path)
	if err != nil {
		return err
	}
	if n > 0 {
		logger.Info("loaded tokens", "count", n, "file", path)
	}
	return nil
}

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
	case os.Getenv("WIRERIFT_TOKEN_FILE") != "":
		return "WIRERIFT_TOKEN_FILE secret"
	}
	return "random"
}

func resolveBootstrapToken(tokenFlag string) (token, source string, err error) {
	if tokenFlag != "" {
		return tokenFlag, "-token flag", nil
	}
	if env := os.Getenv("WIRERIFT_TOKEN"); env != "" {
		return env, "WIRERIFT_TOKEN env", nil
	}
	path := os.Getenv("WIRERIFT_TOKEN_FILE")
	if path == "" {
		return "", "random", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read WIRERIFT_TOKEN_FILE: %w", err)
	}
	token = strings.TrimSpace(string(data))
	if token == "" {
		return "", "", errors.New("WIRERIFT_TOKEN_FILE is empty")
	}
	if len(token) > 4096 {
		return "", "", errors.New("WIRERIFT_TOKEN_FILE exceeds 4096 bytes")
	}
	return token, "WIRERIFT_TOKEN_FILE secret", nil
}

// setEdgeRate applies -edge-rate and -edge-burst (zero keeps the defaults).
func setEdgeRate(cfg *server.Config, rate float64, burst int) error {
	if rate < 0 || burst < 0 {
		return errors.New("-edge-rate and -edge-burst must not be negative")
	}
	cfg.EdgeRatePerIP = rate
	cfg.EdgeRateBurst = burst
	return nil
}

// dropRandomBootstrap disables the random first-run token once the operator has
// a token file: it would otherwise stay valid as an unadvertised second
// credential that also lands in the logs. It returns the new token source.
func dropRandomBootstrap(mgr *auth.Manager, source string) string {
	if source == "random" && mgr.HasFileTokens() {
		mgr.DisableBootstrapToken()
		return "disabled"
	}
	return source
}

// printToken prints the token lines of the banner and returns the token to
// show in the quick-start command. Only an auto-generated token is printed (it
// cannot be known otherwise); a token the operator supplied must not land in logs.
func printToken(w io.Writer, source, token string) string {
	if source == "disabled" {
		fmt.Fprintln(w, "  Token: tokens file in use (no random token)")
		return "<your token>"
	}
	fmt.Fprintf(w, "  Token (%s):\n", source)
	if source == "random" {
		fmt.Fprintf(w, "  %s\n", token)
		return token
	}
	fmt.Fprintln(w, "  (hidden: supplied by you)")
	return "<your token>"
}

// certProvider adapts the TLS manager's certificate list for the dashboard.
func certProvider(m *tlspkg.Manager) func() []dashboard.CertInfo {
	if m == nil {
		return nil
	}
	return func() []dashboard.CertInfo {
		infos := m.CertificateInfos()
		out := make([]dashboard.CertInfo, 0, len(infos))
		for _, c := range infos {
			out = append(out, dashboard.CertInfo{Host: c.Host, Issuer: c.Issuer, NotAfter: c.NotAfter, DaysLeft: c.DaysLeft})
		}
		return out
	}
}

// dashboardHostName turns -dashboard-host into a full host name: a bare label
// belongs to the base domain, anything with a dot is taken as given.
func dashboardHostName(flagValue, domain string) string {
	h := strings.ToLower(strings.TrimSpace(flagValue))
	if h == "" || strings.Contains(h, ".") {
		return h
	}
	return h + "." + domain
}

// publishDashboard serves the dashboard on its own host of the edge when
// -dashboard-host is set. It refuses to do so without HTTPS: the sign-in token
// would cross the internet in clear text.
func publishDashboard(srv *server.Server, dash *dashboard.Dashboard, flagValue, domain, allow string, httpsAvailable bool, logger *slog.Logger) error {
	if _, err := dashboard.ParseAllowList(splitCommaList(allow)); err != nil {
		return fmt.Errorf("-dashboard-allow: %w", err)
	}
	host := dashboardHostName(flagValue, domain)
	if host == "" {
		return nil
	}
	if !httpsAvailable {
		return errors.New("-dashboard-host needs HTTPS (-acme-email, -auto-cert or -dev): the sign-in token must not travel in clear text")
	}
	srv.SetDashboardRoute(host, dash.Handler())
	logger.Info("dashboard published on the edge", "host", host, "allow", allow)
	return nil
}

// applyTLSManager points the server config at the TLS manager's certificates,
// ACME challenge handler and health signals (nil: plain HTTP, nothing to set).
func applyTLSManager(cfg *server.Config, m *tlspkg.Manager) {
	if m == nil {
		return
	}
	cfg.TLSConfig = m.TLSConfig()
	cfg.ACMEChallengeHandler = m.ACMEChallengeHandler()
	cfg.CertificateExpiry = m.EarliestCertificateExpiry
	cfg.PersistenceErrors = m.PersistenceErrors
}

// setupAuth creates the auth manager: bootstrap token (flag > env > secret
// file > random) plus the token file, dropping a random bootstrap token when
// the token file has tokens. It returns the manager and the token source label.
func setupAuth(tokenFlag, tokenFile string, logger *slog.Logger) (*auth.Manager, string, error) {
	bootstrapToken, source, err := resolveBootstrapToken(tokenFlag)
	if err != nil {
		return nil, "", err
	}
	mgr := auth.NewManager(bootstrapToken)
	if err := loadTokenFile(mgr, tokenFile, logger); err != nil {
		return nil, "", err
	}
	return mgr, dropRandomBootstrap(mgr, source), nil
}
