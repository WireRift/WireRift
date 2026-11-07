package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/clientui"
)

const defaultUIPort = 4041

// doUI runs the local web interface: connect, open tunnels and watch traffic
// from a browser.
func doUI(parentCtx context.Context, args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	listen := fs.String("listen", "", "Address to listen on, loopback only (default 127.0.0.1:4041, or the next free port)")
	noOpen := fs.Bool("no-open", false, "Do not open the browser")
	noSave := fs.Bool("no-save", false, "Never store the server or token on disk")
	verbose := fs.Bool("v", false, "Verbose output")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift ui [options]\n\n")
		fmt.Fprintf(os.Stderr, "Open the client's web interface: set the server and token, connect,\nopen and close tunnels, and see the traffic that passes through them.\n\nOptions:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nThe interface listens on the loopback address only, and its address carries a\nkey that is new on every start.\n")
	}
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}

	ln, err := uiListener(*listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	var settings *clientui.Settings
	if !*noSave {
		if path, err := clientui.DefaultSettingsPath(); err == nil {
			settings = clientui.NewSettings(path)
		}
	}
	base := client.DefaultConfig()
	base.Version = version
	mgr := clientui.NewManager(base, settings, createLogger(*verbose))
	opts := parseCommonOptions()
	mgr.Prefill(opts.server, opts.token)

	key, err := clientui.NewKey()
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: clientui.NewHandler(mgr, key, version), ReadHeaderTimeout: 10 * time.Second}
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	go handleSignals(ctx, cancel)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "web interface stopped: %v\n", err)
			cancel()
		}
	}()

	url := "http://" + ln.Addr().String() + "/?k=" + key
	fmt.Printf("WireRift client interface: %s\n", url)
	fmt.Println("Keep this address to yourself: it carries the key. Press Ctrl+C to quit.")
	if !*noOpen {
		openBrowser(url)
	}

	<-ctx.Done()
	mgr.Disconnect()
	shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	return srv.Shutdown(shutdown)
}

// uiListener binds the interface. With no explicit address it tries the
// default port and the next few; an explicit address must be loopback.
func uiListener(listen string) (net.Listener, error) {
	if listen != "" {
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, fmt.Errorf("invalid -listen address: %v", err)
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("-listen must be a loopback address (127.0.0.1, ::1 or localhost): the interface can open tunnels and holds your token")
		}
		return net.Listen("tcp", listen)
	}
	var lastErr error
	for port := defaultUIPort; port < defaultUIPort+10; port++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no free port between %d and %d: %v", defaultUIPort, defaultUIPort+9, lastErr)
}

// browserCommand is the command that opens url on the given operating system.
func browserCommand(goos, url string) *exec.Cmd {
	switch goos {
	case "darwin":
		return exec.Command("open", url)
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return exec.Command("xdg-open", url)
	}
}

// openBrowser asks the desktop to open url; failure is harmless (the address is printed).
func openBrowser(url string) {
	cmd := browserCommand(runtime.GOOS, url)
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}
