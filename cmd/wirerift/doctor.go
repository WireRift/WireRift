package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/diag"
)

// doctor runs the client-side checks and reports them through diag.Report.
type doctor struct{ diag.Report }

const doctorStepTimeout = 5 * time.Second

// doctorAuthTimeout bounds the login step (a var so tests can shorten it).
var doctorAuthTimeout = 3 * doctorStepTimeout

// doDoctor implements "wirerift doctor": it walks from DNS to authentication
// and tells you which step is broken and what to try.
func doDoctor(parentCtx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	server := fs.String("server", "", "Server address (default: localhost:4443)")
	token := fs.String("token", "", "Authentication token")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: wirerift doctor [options]\n\nCheck that this machine can reach and log in to a WireRift server.\n\nOptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(normalizeArgs(args[2:])); err != nil {
		return err
	}
	opts := parseCommonOptions()
	if *server != "" {
		opts.server = *server
	}
	if *token != "" {
		opts.token = *token
	}

	fmt.Printf("WireRift %s\n\n", version)
	failures := runDoctor(parentCtx, os.Stdout, opts.server, opts.token)
	if failures > 0 {
		return fmt.Errorf("doctor found %d problem(s)", failures)
	}
	return nil
}

// runDoctor runs the checks and returns the number of failures. A failing
// step stops the run: later steps depend on it.
func runDoctor(ctx context.Context, out io.Writer, server, token string) int {
	d := &doctor{diag.Report{Out: out}}
	hostPort, useTLS := client.SplitServerAddr(server)
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		d.Add(diag.Fail, "Server address", fmt.Sprintf("%q is not host:port", server),
			"use -server host:port (or tls://host:port), or set WIRERIFT_SERVER")
		return d.Summary()
	}
	mode := "plain TCP"
	if useTLS {
		mode = "TLS"
	}
	d.Add(diag.OK, "Server address", fmt.Sprintf("%s (%s)", hostPort, mode), "")

	if !d.checkDNS(ctx, host) || !d.checkTCP(ctx, hostPort) {
		return d.Summary()
	}
	if !d.checkTransport(ctx, hostPort, host, useTLS) {
		return d.Summary()
	}
	d.checkAuth(ctx, server, token)
	return d.Summary()
}

func (d *doctor) checkDNS(ctx context.Context, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		d.Add(diag.OK, "DNS", "IP address, no lookup needed", "")
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, doctorStepTimeout)
	defer cancel()
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		d.Add(diag.Fail, "DNS", fmt.Sprintf("cannot resolve %s", host), "check the host name and your network/DNS settings")
		return false
	}
	d.Add(diag.OK, "DNS", fmt.Sprintf("%s → %s (%s)", host, addrs[0], ms(time.Since(start))), "")
	return true
}

func (d *doctor) checkTCP(ctx context.Context, hostPort string) bool {
	ctx, cancel := context.WithTimeout(ctx, doctorStepTimeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", hostPort)
	if err != nil {
		d.Add(diag.Fail, "TCP connect", fmt.Sprintf("cannot connect to %s", hostPort),
			"is wirerift-server running, and is the control port open in the firewall?")
		return false
	}
	conn.Close()
	d.Add(diag.OK, "TCP connect", fmt.Sprintf("%s (%s)", hostPort, ms(time.Since(start))), "")
	return true
}

// checkTransport verifies TLS (certificate, expiry) or warns about a
// cleartext control plane on a non-loopback address.
func (d *doctor) checkTransport(ctx context.Context, hostPort, host string, useTLS bool) bool {
	if !useTLS {
		if isLoopback(host) {
			d.Add(diag.OK, "Encryption", "plain TCP on loopback", "")
		} else {
			d.Add(diag.Warn, "Encryption", "the control plane is not encrypted: your token travels in cleartext",
				"ask the operator for TLS (-control-tls-cert) and use tls://"+hostPort)
		}
		return true
	}

	cfg, err := client.ControlTLSConfig(nil)
	if err != nil {
		d.Add(diag.Fail, "TLS", err.Error(), "check the WIRERIFT_TLS_CA file")
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, doctorStepTimeout)
	defer cancel()
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", hostPort)
	if err != nil {
		d.Add(diag.Fail, "TLS", "handshake failed: "+err.Error(),
			"for a private or self-signed CA set WIRERIFT_TLS_CA=/path/to/ca.pem; for a plain server drop the tls:// prefix")
		return false
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	detail := tlsVersionName(state.Version)
	status, hint := diag.OK, ""
	if len(state.PeerCertificates) > 0 {
		days := int(time.Until(state.PeerCertificates[0].NotAfter).Hours() / 24)
		detail += fmt.Sprintf(", certificate valid, expires in %d days", days)
		if days < 14 {
			status, hint = diag.Warn, "the server certificate expires soon; tell the operator to renew it"
		}
	}
	d.Add(status, "TLS", detail, hint)
	return true
}

func (d *doctor) checkAuth(ctx context.Context, server, token string) {
	if token == "" {
		d.Add(diag.Warn, "Authentication", "no token set, skipped", "pass -token or set WIRERIFT_TOKEN")
		return
	}
	cfg := client.DefaultConfig()
	cfg.ServerAddr = server
	cfg.Token = token
	cfg.Reconnect = false
	c := client.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	start := time.Now()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Connect() }()
	select {
	case err := <-errCh:
		if err != nil {
			d.Add(diag.Fail, "Authentication", err.Error(), "check the token (it is case-sensitive) and that the account is active")
			return
		}
		c.Close()
		d.Add(diag.OK, "Authentication", fmt.Sprintf("logged in (%s)", ms(time.Since(start))), "")
	case <-time.After(doctorAuthTimeout):
		c.Close()
		d.Add(diag.Fail, "Authentication", "no answer from the server", "the server accepted the connection but is not speaking the WireRift protocol, or is overloaded")
	case <-ctx.Done():
		c.Close()
	}
}

func ms(d time.Duration) string { return fmt.Sprintf("%dms", d.Milliseconds()) }

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("TLS 0x%04x", v)
}
