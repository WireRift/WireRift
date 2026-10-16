package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	tlspkg "github.com/wirerift/wirerift/internal/tls"
)

// Defaults for -dev: loopback only and unprivileged ports, so nothing needs
// root and nothing is reachable from the network.
const (
	devControlAddr = "127.0.0.1:4443"
	devHTTPAddr    = "127.0.0.1:8080"
	devHTTPSAddr   = "127.0.0.1:8443"
	devDomain      = "localhost"
)

// devSetup is the result of preparing -dev mode.
type devSetup struct {
	CA       *tlspkg.LocalCA
	Provider *tlspkg.LeafProvider
	Port     int // HTTPS port used in public URLs
}

// devOptions are the server options -dev may adjust. The explicit set holds
// the flags (or environment variables) the user chose themselves; those are
// never overridden.
type devOptions struct {
	Domain, Control, HTTP, HTTPS *string
	Explicit                     map[string]bool
	CADir                        string
	ACMEEmail                    string
}

// setupDev applies -dev defaults and prepares HTTPS from the local CA.
func setupDev(o devOptions) (*devSetup, error) {
	if o.ACMEEmail != "" {
		return nil, errors.New("-dev uses a local CA and cannot be combined with -acme-email")
	}
	if !o.Explicit["domain"] {
		*o.Domain = devDomain
	}
	if !tlspkg.LocalNamePermitted(*o.Domain) || net.ParseIP(*o.Domain) != nil {
		return nil, fmt.Errorf("-dev only supports domains under .localhost or .test (got %q): the local CA is restricted to them", *o.Domain)
	}
	if !o.Explicit["control"] {
		*o.Control = devControlAddr
	}
	if !o.Explicit["http"] {
		*o.HTTP = devHTTPAddr
	}
	if !o.Explicit["https"] {
		*o.HTTPS = devHTTPSAddr
	}

	_, portStr, err := net.SplitHostPort(*o.HTTPS)
	if err != nil {
		return nil, fmt.Errorf("invalid -https address %q: %v", *o.HTTPS, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid -https port %q", portStr)
	}

	dir, err := resolveCADir(o.CADir)
	if err != nil {
		return nil, err
	}
	ca, err := tlspkg.LoadOrCreateLocalCA(dir)
	if err != nil {
		return nil, err
	}
	provider, err := ca.NewLeafProvider(*o.Domain)
	if err != nil {
		return nil, err
	}
	return &devSetup{CA: ca, Provider: provider, Port: port}, nil
}

// explicitSettings returns which options the user set via flag or environment.
func explicitSettings(visited map[string]bool) map[string]bool {
	set := map[string]bool{}
	for k, v := range visited {
		set[k] = v
	}
	if os.Getenv("WIRERIFT_DOMAIN") != "" {
		set["domain"] = true
	}
	if os.Getenv("WIRERIFT_CONTROL_ADDR") != "" {
		set["control"] = true
	}
	if os.Getenv("WIRERIFT_HTTP_ADDR") != "" {
		set["http"] = true
	}
	return set
}

// visitedFlags returns the names of the flags that were set on the command line.
func visitedFlags(fs *flag.FlagSet) map[string]bool {
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	return visited
}

// printBanner prints the -dev lines of the startup banner. A nil receiver
// (not in -dev mode) prints nothing.
func (d *devSetup) printBanner(w io.Writer, httpsAddr, domain string) {
	if d == nil {
		return
	}
	fmt.Fprintf(w, "  HTTPS:     %s  (local CA)\n", httpsAddr)
	fmt.Fprintf(w, "  Tunnels:   https://<name>.%s:%d\n", domain, d.Port)
	if tlspkg.IsTrustedBySystem(d.CA) {
		fmt.Fprintln(w, "  Local CA:  trusted by this system")
	} else {
		fmt.Fprintln(w, "  Local CA:  NOT trusted yet; run once: wirerift-server ca trust")
	}
}
