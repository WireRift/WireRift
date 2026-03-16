package main

import (
	"bufio"
	"context"
	"encoding/json"
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

	"github.com/wirerift/wirerift/internal/client"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		printUsage()
		return fmt.Errorf("")
	}

	cmd := args[1]
	switch cmd {
	case "http":
		return doHTTP(context.Background(), args)
	case "tcp":
		return doTCP(context.Background(), args)
	case "serve":
		return doServe(context.Background(), args)
	case "start":
		return doStart(context.Background(), args)
	case "list":
		return doList(args)
	case "config":
		return doConfig(args)
	case "version":
		fmt.Printf("WireRift %s (commit: %s, built: %s)\n", version, commit, date)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		return fmt.Errorf("")
	}
	return nil
}

func printUsage() {
	fmt.Println(`WireRift - Expose localhost to the world

Usage:
  wirerift <command> [options]

Commands:
  http <local-port> [subdomain]   Create an HTTP tunnel
  tcp <local-port>                Create a TCP tunnel
  serve <directory>               Serve static files via HTTP tunnel
  start [config-file]             Start tunnels from config file
  list                            List active tunnels
  config                          Show/edit configuration
  version                         Show version information
  help                            Show this help

Examples:
  wirerift http 8080                    Create HTTP tunnel on port 8080
  wirerift http 8080 myapp              Create HTTP tunnel with subdomain
  wirerift http 8080 -pin 1234          Create PIN-protected tunnel
  wirerift http 8080 -whitelist 1.2.3.4 Create IP-restricted tunnel
  wirerift tcp 25565                    Create TCP tunnel on port 25565
  wirerift serve ./dist                 Serve static files and tunnel
  wirerift start wirerift.yaml          Start tunnels from config

Environment Variables:
  WIRERIFT_SERVER    Server address (default: localhost:4443)
  WIRERIFT_TOKEN     Authentication token`)
}

// Common flags and options
type commonOptions struct {
	server string
	token  string
}

func parseCommonOptions() commonOptions {
	return commonOptions{
		server: getEnv("WIRERIFT_SERVER", "localhost:4443"),
		token:  getEnv("WIRERIFT_TOKEN", ""),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// normalizeDashes converts --flag to -flag so both styles work.
// Go's flag package only supports single-dash; this makes CLI more intuitive.
func normalizeDashes(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.HasPrefix(a, "--") && !strings.HasPrefix(a, "---") && a != "--" {
			out[i] = a[1:] // "--token" → "-token"
		} else {
			out[i] = a
		}
	}
	return out
}

// handleSignals cancels the context on interrupt/SIGTERM.
func handleSignals(ctx context.Context, cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	select {
	case <-sigCh:
		cancel()
	case <-ctx.Done():
	}
}

func createLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// doHTTP creates an HTTP tunnel.
func doHTTP(parentCtx context.Context, args []string) error {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	subdomain := fs.String("subdomain", "", "Requested subdomain")
	whitelist := fs.String("whitelist", "", "Comma-separated IP whitelist (e.g., 1.2.3.4,10.0.0.0/8)")
	pin := fs.String("pin", "", "PIN protection for tunnel access")
	auth := fs.String("auth", "", "Basic auth in user:pass format (e.g., admin:secret)")
	inspect := fs.Bool("inspect", false, "Enable traffic inspection")
	header := fs.String("header", "", "Custom response headers, comma-separated Key:Value (e.g., X-Robots:noindex,Cache-Control:no-store)")
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift http [options] <local-port> [subdomain]\n\n")
		fmt.Fprintf(os.Stderr, "Create an HTTP tunnel.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  wirerift http 8080\n")
		fmt.Fprintf(os.Stderr, "  wirerift http 8080 myapp\n")
		fmt.Fprintf(os.Stderr, "  wirerift http -subdomain myapp 8080\n")
	}

	if err := fs.Parse(normalizeDashes(args[2:])); err != nil {
		return err
	}

	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	fargs := fs.Args()
	if len(fargs) < 1 {
		fs.Usage()
		return fmt.Errorf("missing port argument")
	}

	localPort, err := strconv.Atoi(fargs[0])
	if err != nil {
		return fmt.Errorf("invalid port: %s", fargs[0])
	}
	if localPort < 1 || localPort > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", localPort)
	}

	// Subdomain from positional arg or flag
	reqSubdomain := *subdomain
	if len(fargs) > 1 && reqSubdomain == "" {
		reqSubdomain = fargs[1]
	}

	logger := createLogger(*verbose)

	// Create client
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = opts.server
	clientCfg.Token = opts.token
	clientCfg.Reconnect = false
	c := client.New(clientCfg, logger)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Signal handling: cancel context on interrupt
	go handleSignals(ctx, cancel)

	// Connect to server
	if err := c.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	// Create tunnel
	var tunnelOpts []client.HTTPOption
	if reqSubdomain != "" {
		tunnelOpts = append(tunnelOpts, client.WithSubdomain(reqSubdomain))
	}
	if *whitelist != "" {
		ips := strings.Split(*whitelist, ",")
		for i := range ips {
			ips[i] = strings.TrimSpace(ips[i])
		}
		tunnelOpts = append(tunnelOpts, client.WithAllowedIPs(ips))
	}
	if *pin != "" {
		tunnelOpts = append(tunnelOpts, client.WithPIN(*pin))
	}
	if *auth != "" {
		parts := strings.SplitN(*auth, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid -auth format, expected user:pass")
		}
		tunnelOpts = append(tunnelOpts, client.WithAuth(parts[0], parts[1]))
	}
	if *inspect {
		tunnelOpts = append(tunnelOpts, client.WithInspect())
	}
	if *header != "" {
		headers := parseHeaders(*header)
		tunnelOpts = append(tunnelOpts, client.WithHeaders(headers))
	}

	tunnel, err := c.HTTP(fmt.Sprintf("localhost:%d", localPort), tunnelOpts...)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %v", err)
	}

	fmt.Printf("HTTP tunnel created: %s -> http://localhost:%d\n", tunnel.PublicURL, localPort)
	if tunnel.Subdomain != "" {
		fmt.Printf("Subdomain: %s\n", tunnel.Subdomain)
	}
	if *whitelist != "" {
		fmt.Printf("IP Whitelist: %s\n", *whitelist)
	}
	if *pin != "" {
		fmt.Printf("PIN Protected: yes\n")
	}
	if *auth != "" {
		fmt.Printf("Basic Auth: enabled\n")
	}
	if *inspect {
		fmt.Printf("Inspect: enabled\n")
	}
	if *header != "" {
		fmt.Printf("Custom Headers: %s\n", *header)
	}

	// Wait for context
	<-ctx.Done()
	c.Close()
	return nil
}

// doTCP creates a TCP tunnel.
func doTCP(parentCtx context.Context, args []string) error {
	fs := flag.NewFlagSet("tcp", flag.ContinueOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift tcp [options] <local-port>\n\n")
		fmt.Fprintf(os.Stderr, "Create a TCP tunnel.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  wirerift tcp 25565\n")
		fmt.Fprintf(os.Stderr, "  wirerift tcp 22\n")
	}

	if err := fs.Parse(normalizeDashes(args[2:])); err != nil {
		return err
	}

	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	fargs := fs.Args()
	if len(fargs) < 1 {
		fs.Usage()
		return fmt.Errorf("missing port argument")
	}

	localPort, err := strconv.Atoi(fargs[0])
	if err != nil {
		return fmt.Errorf("invalid port: %s", fargs[0])
	}
	if localPort < 1 || localPort > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", localPort)
	}

	logger := createLogger(*verbose)

	// Create client
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = opts.server
	clientCfg.Token = opts.token
	clientCfg.Reconnect = false
	c := client.New(clientCfg, logger)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Signal handling: cancel context on interrupt
	go handleSignals(ctx, cancel)

	// Connect to server
	if err := c.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	// Create tunnel
	tunnel, err := c.TCP(fmt.Sprintf("localhost:%d", localPort), 0)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %v", err)
	}

	fmt.Printf("TCP tunnel created: %s:%d -> localhost:%d\n", opts.server, tunnel.Port, localPort)

	// Wait for context
	<-ctx.Done()
	c.Close()
	return nil
}

// doStart starts tunnels from a config file.
func doStart(parentCtx context.Context, args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift start [options] [config-file]\n\n")
		fmt.Fprintf(os.Stderr, "Start tunnels from config file.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDefault config file: wirerift.yaml (also supports .json)\n")
	}

	if err := fs.Parse(normalizeDashes(args[2:])); err != nil {
		return err
	}

	configFile := "wirerift.yaml"
	if len(fs.Args()) > 0 {
		configFile = fs.Args()[0]
	} else if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Fallback to JSON if YAML not found
		if _, err := os.Stat("wirerift.json"); err == nil {
			configFile = "wirerift.json"
		}
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	if *verbose {
		fmt.Printf("Loaded config from %s\n", configFile)
		fmt.Printf("Server: %s\n", cfg.Server)
		fmt.Printf("Tunnels: %d\n", len(cfg.Tunnels))
	}

	logger := createLogger(*verbose)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Signal handling: cancel context on interrupt
	go handleSignals(ctx, cancel)

	startCfg := client.DefaultConfig()
	startCfg.ServerAddr = cfg.Server
	startCfg.Token = cfg.Token
	startCfg.Reconnect = false
	c := client.New(startCfg, logger)

	// Connect to server
	if err := c.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	for _, t := range cfg.Tunnels {
		switch t.Type {
		case "http", "":
			var opts []client.HTTPOption
			if t.Subdomain != "" {
				opts = append(opts, client.WithSubdomain(t.Subdomain))
			}
			if t.Whitelist != "" {
				ips := strings.Split(t.Whitelist, ",")
				for i := range ips {
					ips[i] = strings.TrimSpace(ips[i])
				}
				opts = append(opts, client.WithAllowedIPs(ips))
			}
			if t.PIN != "" {
				opts = append(opts, client.WithPIN(t.PIN))
			}
			if t.Auth != "" {
				parts := strings.SplitN(t.Auth, ":", 2)
				if len(parts) == 2 {
					opts = append(opts, client.WithAuth(parts[0], parts[1]))
				}
			}
			if t.Inspect {
				opts = append(opts, client.WithInspect())
			}
			if t.Headers != "" {
				opts = append(opts, client.WithHeaders(parseHeaders(t.Headers)))
			}
			tunnel, err := c.HTTP(fmt.Sprintf("localhost:%d", t.LocalPort), opts...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create HTTP tunnel: %v\n", err)
				continue
			}
			fmt.Printf("HTTP tunnel: %s -> localhost:%d\n", tunnel.PublicURL, t.LocalPort)
		case "tcp":
			tunnel, err := c.TCP(fmt.Sprintf("localhost:%d", t.LocalPort), 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create TCP tunnel: %v\n", err)
				continue
			}
			fmt.Printf("TCP tunnel: port %d -> localhost:%d\n", tunnel.Port, t.LocalPort)
		default:
			fmt.Fprintf(os.Stderr, "Unknown tunnel type: %s\n", t.Type)
		}
	}

	fmt.Println("All tunnels started. Press Ctrl+C to stop.")

	<-ctx.Done()
	c.Close()
	return nil
}

// TunnelConfig represents a tunnel in the config file
type TunnelConfig struct {
	Type      string `json:"type" yaml:"type"`
	LocalPort int    `json:"local_port" yaml:"local_port"`
	Subdomain string `json:"subdomain,omitempty" yaml:"subdomain"`
	Whitelist string `json:"whitelist,omitempty" yaml:"whitelist"`
	PIN       string `json:"pin,omitempty" yaml:"pin"`
	Auth      string `json:"auth,omitempty" yaml:"auth"`
	Inspect   bool   `json:"inspect,omitempty" yaml:"inspect"`
	Headers   string `json:"headers,omitempty" yaml:"headers"`
}

// ConfigFile represents the config file structure
type ConfigFile struct {
	Server  string         `json:"server" yaml:"server"`
	Token   string         `json:"token" yaml:"token"`
	Tunnels []TunnelConfig `json:"tunnels" yaml:"tunnels"`
}

func loadConfig(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &ConfigFile{
		Server: getEnv("WIRERIFT_SERVER", "localhost:4443"),
		Token:  getEnv("WIRERIFT_TOKEN", ""),
	}

	// JSON files are parsed with stdlib encoder (reliable)
	if strings.HasSuffix(path, ".json") {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse JSON config: %w", err)
		}
		// Apply env overrides
		if cfg.Server == "" {
			cfg.Server = getEnv("WIRERIFT_SERVER", "localhost:4443")
		}
		if cfg.Token == "" {
			cfg.Token = getEnv("WIRERIFT_TOKEN", "")
		}
		return cfg, nil
	}

	// YAML files are parsed with a simple line-based parser.
	// Supports flat key:value pairs and a single "tunnels:" list.
	// For complex configs, use JSON format instead.
	return loadYAMLConfig(data, cfg)
}

// loadYAMLConfig parses a simple YAML config file.
// Limitations: flat key:value only, single-level "tunnels:" list,
// no nested objects, no multi-line values, no anchors/aliases.
// For full YAML support, use wirerift.json instead.
func loadYAMLConfig(data []byte, cfg *ConfigFile) (*ConfigFile, error) {
	lines := strings.Split(string(data), "\n")
	currentSection := ""
	tunnelIdx := -1

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "tunnels:") {
			currentSection = "tunnels"
			continue
		}

		if currentSection == "tunnels" && strings.HasPrefix(line, "- ") {
			cfg.Tunnels = append(cfg.Tunnels, TunnelConfig{})
			tunnelIdx++
			line = strings.TrimPrefix(line, "- ")
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

		if currentSection == "tunnels" && tunnelIdx >= 0 {
			switch key {
			case "type":
				cfg.Tunnels[tunnelIdx].Type = value
			case "local_port":
				port, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid local_port %q: %w", value, err)
				}
				cfg.Tunnels[tunnelIdx].LocalPort = port
			case "subdomain":
				cfg.Tunnels[tunnelIdx].Subdomain = value
			case "whitelist":
				cfg.Tunnels[tunnelIdx].Whitelist = value
			case "pin":
				cfg.Tunnels[tunnelIdx].PIN = value
			case "auth":
				cfg.Tunnels[tunnelIdx].Auth = value
			case "inspect":
				cfg.Tunnels[tunnelIdx].Inspect = value == "true"
			case "headers":
				cfg.Tunnels[tunnelIdx].Headers = value
			}
		} else {
			switch key {
			case "server":
				cfg.Server = value
			case "token":
				cfg.Token = value
			}
		}
	}

	return cfg, nil
}

// parseHeaders parses a comma-separated "Key:Value" string into a map.
func parseHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

// doServe starts a static file server and creates an HTTP tunnel to it.
func doServe(parentCtx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	subdomain := fs.String("subdomain", "", "Requested subdomain")
	whitelist := fs.String("whitelist", "", "Comma-separated IP whitelist (e.g., 1.2.3.4,10.0.0.0/8)")
	pin := fs.String("pin", "", "PIN protection for tunnel access")
	auth := fs.String("auth", "", "Basic auth in user:pass format (e.g., admin:secret)")
	inspect := fs.Bool("inspect", false, "Enable traffic inspection")
	header := fs.String("header", "", "Custom response headers, comma-separated Key:Value (e.g., X-Robots:noindex,Cache-Control:no-store)")
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift serve [options] <directory>\n\n")
		fmt.Fprintf(os.Stderr, "Serve static files via an HTTP tunnel.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  wirerift serve ./dist\n")
		fmt.Fprintf(os.Stderr, "  wirerift serve -subdomain myapp ./public\n")
	}

	if err := fs.Parse(normalizeDashes(args[2:])); err != nil {
		return err
	}

	fargs := fs.Args()
	if len(fargs) < 1 {
		fs.Usage()
		return fmt.Errorf("missing directory argument")
	}

	dir := fargs[0]

	// Verify directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot access directory: %v", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	// Start a local file server on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start file server: %v", err)
	}
	localPort := listener.Addr().(*net.TCPAddr).Port

	fileSrv := &http.Server{Handler: http.FileServer(http.Dir(dir))}
	go fileSrv.Serve(listener)

	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	logger := createLogger(*verbose)

	// Create client
	clientCfg := client.DefaultConfig()
	clientCfg.ServerAddr = opts.server
	clientCfg.Token = opts.token
	clientCfg.Reconnect = false
	c := client.New(clientCfg, logger)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	go handleSignals(ctx, cancel)

	if err := c.Connect(); err != nil {
		listener.Close()
		return fmt.Errorf("failed to connect: %v", err)
	}

	// Build tunnel options
	var tunnelOpts []client.HTTPOption
	if *subdomain != "" {
		tunnelOpts = append(tunnelOpts, client.WithSubdomain(*subdomain))
	}
	if *whitelist != "" {
		ips := strings.Split(*whitelist, ",")
		for i := range ips {
			ips[i] = strings.TrimSpace(ips[i])
		}
		tunnelOpts = append(tunnelOpts, client.WithAllowedIPs(ips))
	}
	if *pin != "" {
		tunnelOpts = append(tunnelOpts, client.WithPIN(*pin))
	}
	if *auth != "" {
		parts := strings.SplitN(*auth, ":", 2)
		if len(parts) != 2 {
			listener.Close()
			return fmt.Errorf("invalid -auth format, expected user:pass")
		}
		tunnelOpts = append(tunnelOpts, client.WithAuth(parts[0], parts[1]))
	}
	if *inspect {
		tunnelOpts = append(tunnelOpts, client.WithInspect())
	}
	if *header != "" {
		tunnelOpts = append(tunnelOpts, client.WithHeaders(parseHeaders(*header)))
	}

	tunnel, err := c.HTTP(fmt.Sprintf("localhost:%d", localPort), tunnelOpts...)
	if err != nil {
		listener.Close()
		return fmt.Errorf("failed to create tunnel: %v", err)
	}

	fmt.Printf("Serving %s at %s\n", dir, tunnel.PublicURL)

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	fileSrv.Shutdown(shutdownCtx)
	c.Close()
	return nil
}

// doList lists active tunnels.
func doList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	jsonOutput := fs.Bool("json", false, "JSON output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift list [options]\n\n")
		fmt.Fprintf(os.Stderr, "List active tunnels.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(normalizeDashes(args[2:])); err != nil {
		return err
	}

	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	// Query the dashboard API
	url := fmt.Sprintf("http://%s/api/tunnels", strings.Split(opts.server, ":")[0]+":4040")

	req, _ := http.NewRequest("GET", url, nil)
	if opts.token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.token)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if *jsonOutput {
		fmt.Println(string(body))
		return nil
	}

	var tunnels []struct {
		ID        string    `json:"id"`
		Type      string    `json:"type"`
		URL       string    `json:"url"`
		Port      int       `json:"port"`
		Target    string    `json:"target"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
	}

	if err := json.Unmarshal(body, &tunnels); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if len(tunnels) == 0 {
		fmt.Println("No active tunnels")
		return nil
	}

	fmt.Println("Active tunnels:")
	fmt.Println()
	for _, t := range tunnels {
		if t.Type == "http" {
			fmt.Printf("  %s  %s -> %s  (%s)\n", t.ID, t.URL, t.Target, t.Status)
		} else {
			fmt.Printf("  %s  tcp://%s:%d -> %s  (%s)\n", t.ID, opts.server, t.Port, t.Target, t.Status)
		}
	}
	return nil
}

// doConfig shows/edits configuration.
func doConfig(args []string) error {
	if len(args) < 3 {
		showConfig()
		return nil
	}

	cmd := args[2]
	switch cmd {
	case "show":
		showConfig()
	case "init":
		initConfig()
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", cmd)
		fmt.Fprintf(os.Stderr, "Usage: wirerift config [show|init]\n")
		return fmt.Errorf("")
	}
	return nil
}

func showConfig() {
	configFile := "wirerift.yaml"
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Println("No configuration file found.")
		fmt.Println("Run 'wirerift config init' to create one.")
		return
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}

func initConfig() {
	configFile := "wirerift.yaml"

	if _, err := os.Stat(configFile); err == nil {
		fmt.Printf("Config file %s already exists. Overwrite? (y/N): ", configFile)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) != "y" {
			fmt.Println("Aborted")
			return
		}
	}

	configContent := `# WireRift configuration file
server: localhost:4443
token: ""  # Set your API token here

tunnels:
  - type: http
    local_port: 8080
    subdomain: ""       # Leave empty for random subdomain
    # whitelist: ""     # Comma-separated IPs (e.g., 1.2.3.4,10.0.0.0/8)
    # pin: ""           # PIN protection for tunnel access
  # - type: tcp
  #   local_port: 25565
`

	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created config file: %s\n", configFile)
	fmt.Println("Edit the file to configure your tunnels.")
}
