package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
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
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "http":
		runHTTP()
	case "tcp":
		runTCP()
	case "start":
		runStart()
	case "list":
		runList()
	case "config":
		runConfig()
	case "version":
		fmt.Printf("WireRift %s (commit: %s, built: %s)\n", version, commit, date)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`WireRift - Expose localhost to the world

Usage:
  wirerift <command> [options]

Commands:
  http <local-port> [subdomain]   Create an HTTP tunnel
  tcp <local-port>                Create a TCP tunnel
  start [config-file]             Start tunnels from config file
  list                            List active tunnels
  config                          Show/edit configuration
  version                         Show version information
  help                            Show this help

Examples:
  wirerift http 8080                    Create HTTP tunnel on port 8080
  wirerift http 8080 myapp              Create HTTP tunnel with subdomain
  wirerift tcp 25565                    Create TCP tunnel on port 25565
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

func createLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// runHTTP creates an HTTP tunnel
func runHTTP() {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	subdomain := fs.String("subdomain", "", "Requested subdomain")
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

	fs.Parse(os.Args[2:])

	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		os.Exit(1)
	}

	localPort, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", args[0])
		os.Exit(1)
	}

	// Subdomain from positional arg or flag
	reqSubdomain := *subdomain
	if len(args) > 1 && reqSubdomain == "" {
		reqSubdomain = args[1]
	}

	logger := createLogger(*verbose)

	// Create client
	c := client.New(client.Config{
		ServerAddr: opts.server,
		Token:      opts.token,
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if *verbose {
			fmt.Println("\nShutting down...")
		}
		cancel()
	}()

	// Connect to server
	if err := c.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}

	// Create tunnel
	var tunnelOpts []client.HTTPOption
	if reqSubdomain != "" {
		tunnelOpts = append(tunnelOpts, client.WithSubdomain(reqSubdomain))
	}

	tunnel, err := c.HTTP(fmt.Sprintf("localhost:%d", localPort), tunnelOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create tunnel: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("HTTP tunnel created: %s -> http://localhost:%d\n", tunnel.PublicURL, localPort)
	if tunnel.Subdomain != "" {
		fmt.Printf("Subdomain: %s\n", tunnel.Subdomain)
	}

	if *verbose {
		fmt.Println("Press Ctrl+C to stop")
	}

	// Wait for context
	<-ctx.Done()
	c.Close()
}

// runTCP creates a TCP tunnel
func runTCP() {
	fs := flag.NewFlagSet("tcp", flag.ExitOnError)
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

	fs.Parse(os.Args[2:])

	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		os.Exit(1)
	}

	localPort, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", args[0])
		os.Exit(1)
	}

	logger := createLogger(*verbose)

	// Create client
	c := client.New(client.Config{
		ServerAddr: opts.server,
		Token:      opts.token,
	}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if *verbose {
			fmt.Println("\nShutting down...")
		}
		cancel()
	}()

	// Connect to server
	if err := c.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}

	// Create tunnel
	tunnel, err := c.TCP(fmt.Sprintf("localhost:%d", localPort), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create tunnel: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("TCP tunnel created: %s:%d -> localhost:%d\n", opts.server, tunnel.Port, localPort)

	if *verbose {
		fmt.Println("Press Ctrl+C to stop")
	}

	// Wait for context
	<-ctx.Done()
	c.Close()
}

// runStart starts tunnels from a config file
func runStart() {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift start [options] [config-file]\n\n")
		fmt.Fprintf(os.Stderr, "Start tunnels from config file.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDefault config file: wirerift.yaml\n")
	}

	fs.Parse(os.Args[2:])

	configFile := "wirerift.yaml"
	if len(fs.Args()) > 0 {
		configFile = fs.Args()[0]
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("Loaded config from %s\n", configFile)
		fmt.Printf("Server: %s\n", cfg.Server)
		fmt.Printf("Tunnels: %d\n", len(cfg.Tunnels))
	}

	logger := createLogger(*verbose)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	c := client.New(client.Config{
		ServerAddr: cfg.Server,
		Token:      cfg.Token,
	}, logger)

	// Connect to server
	if err := c.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}

	for _, t := range cfg.Tunnels {
		switch t.Type {
		case "http", "":
			var opts []client.HTTPOption
			if t.Subdomain != "" {
				opts = append(opts, client.WithSubdomain(t.Subdomain))
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
}

// TunnelConfig represents a tunnel in the config file
type TunnelConfig struct {
	Type      string `yaml:"type"`
	LocalPort int    `yaml:"local_port"`
	Subdomain string `yaml:"subdomain"`
}

// ConfigFile represents the config file structure
type ConfigFile struct {
	Server  string         `yaml:"server"`
	Token   string         `yaml:"token"`
	Tunnels []TunnelConfig `yaml:"tunnels"`
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

	// Simple YAML parsing (basic implementation)
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
				cfg.Tunnels[tunnelIdx].LocalPort, _ = strconv.Atoi(value)
			case "subdomain":
				cfg.Tunnels[tunnelIdx].Subdomain = value
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

// runList lists active tunnels
func runList() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	jsonOutput := fs.Bool("json", false, "JSON output")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift list [options]\n\n")
		fmt.Fprintf(os.Stderr, "List active tunnels.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if *jsonOutput {
		fmt.Println(string(body))
		return
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
		fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	if len(tunnels) == 0 {
		fmt.Println("No active tunnels")
		return
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
}

// runConfig shows/edits configuration
func runConfig() {
	if len(os.Args) < 3 {
		showConfig()
		return
	}

	cmd := os.Args[2]
	switch cmd {
	case "show":
		showConfig()
	case "init":
		initConfig()
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", cmd)
		fmt.Fprintf(os.Stderr, "Usage: wirerift config [show|init]\n")
		os.Exit(1)
	}
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
    subdomain: ""  # Leave empty for random subdomain
  # - type: tcp
  #   local_port: 25565
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created config file: %s\n", configFile)
	fmt.Println("Edit the file to configure your tunnels.")
}
