package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wirerift/wirerift/internal/diag"
	tlspkg "github.com/wirerift/wirerift/internal/tls"
)

// doctorOptions are the settings the server would start with.
type doctorOptions struct {
	Domain, Control, HTTP, HTTPS string
	DashboardBind                string
	DashboardPort                int
	TCPRange                     string
	CertDir, CADir               string
	ACMEEmail                    string
	DashboardTLS                 bool

	// lookupHost is replaceable in tests (default: system resolver).
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

const (
	certWarnWindow = 14 * 24 * time.Hour
	maxCertsScan   = 200
)

// runServerDoctor implements "wirerift-server doctor": it checks, without
// starting anything, whether this machine can run the server as configured.
func runServerDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := doctorOptions{}
	fs.StringVar(&o.Control, "control", ":4443", "")
	fs.StringVar(&o.HTTP, "http", ":80", "")
	fs.StringVar(&o.HTTPS, "https", ":443", "")
	fs.IntVar(&o.DashboardPort, "dashboard-port", 4040, "")
	fs.StringVar(&o.DashboardBind, "dashboard-bind", "127.0.0.1", "")
	fs.StringVar(&o.Domain, "domain", "wirerift.com", "")
	fs.StringVar(&o.TCPRange, "tcp-ports", "20000-29999", "")
	fs.StringVar(&o.CertDir, "cert-dir", "certs", "")
	fs.StringVar(&o.CADir, "ca-dir", "", "")
	fs.StringVar(&o.ACMEEmail, "acme-email", "", "")
	dashCert := fs.String("dashboard-tls-cert", "", "")
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return fmt.Errorf("doctor: %v\n\nusage: wirerift-server doctor [-control A] [-http A] [-https A] [-dashboard-port N] [-domain D] [-tcp-ports A-B] [-cert-dir DIR] [-acme-email E]", err)
	}
	o.DashboardTLS = *dashCert != ""

	// The same environment fallbacks the server applies.
	given := visitedFlags(fs) // command-line flags win over the environment
	if v := os.Getenv("WIRERIFT_DOMAIN"); v != "" && !given["domain"] {
		o.Domain = v
	}
	if v := os.Getenv("WIRERIFT_CONTROL_ADDR"); v != "" && !given["control"] {
		o.Control = v
	}
	if v := os.Getenv("WIRERIFT_HTTP_ADDR"); v != "" && !given["http"] {
		o.HTTP = v
	}

	fmt.Fprintf(out, "WireRift Server %s\n\n", version)
	if failures := runServerChecks(context.Background(), out, o); failures > 0 {
		return fmt.Errorf("doctor found %d problem(s)", failures)
	}
	return nil
}

// runServerChecks runs every check and returns the number of failures.
func runServerChecks(ctx context.Context, out io.Writer, o doctorOptions) int {
	r := &diag.Report{Out: out}
	r.Add(diag.OK, "Configuration", fmt.Sprintf("domain %s, certificates in %s", o.Domain, o.CertDir), "")

	checkPort(r, "Control port", o.Control, "the control plane (clients connect here)")
	checkPort(r, "HTTP port", o.HTTP, "the HTTP edge and Let's Encrypt HTTP-01")
	checkPort(r, "HTTPS port", o.HTTPS, "the HTTPS edge")
	checkPort(r, "Dashboard port", net.JoinHostPort(o.DashboardBind, strconv.Itoa(o.DashboardPort)), "the dashboard")
	if ip := net.ParseIP(o.DashboardBind); (ip == nil || !ip.IsLoopback()) && !o.DashboardTLS {
		r.Add(diag.Warn, "Dashboard", fmt.Sprintf("listens on %s over plain HTTP: tokens would cross the network in cleartext", o.DashboardBind),
			"use -dashboard-tls-cert/-key, or keep the default 127.0.0.1 and reach it through an SSH tunnel")
	}
	checkTCPRange(r, o.TCPRange)
	checkCertDir(r, o.CertDir)
	checkCertificates(r, o.CertDir)
	checkWildcardDNS(ctx, r, o)
	checkLocalCA(r, o.CADir)
	if o.ACMEEmail != "" && !strings.HasSuffix(o.HTTP, ":80") {
		r.Add(diag.Warn, "Let's Encrypt", "-acme-email is set but the HTTP edge is not on port 80",
			"HTTP-01 validation connects to port 80 of this server: forward public :80 to "+o.HTTP)
	}
	return r.Summary()
}

// checkPort verifies that addr can be bound right now (and releases it).
func checkPort(r *diag.Report, name, addr, purpose string) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		ln.Close()
		r.Add(diag.OK, name, addr+" is free", "")
		return
	}
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		r.Add(diag.Fail, name, fmt.Sprintf("%s is already in use; needed for %s", addr, purpose),
			"stop the other program, or choose another address with the matching flag")
	case errors.Is(err, os.ErrPermission):
		hint := "use a port above 1023 (for example -http :8080), or run with -dev for local work"
		if runtime.GOOS == "linux" {
			hint = "ports below 1024 need root or: sudo setcap 'cap_net_bind_service=+ep' wirerift-server " +
				"(or sysctl net.ipv4.ip_unprivileged_port_start=80); otherwise use a higher port"
		}
		r.Add(diag.Fail, name, fmt.Sprintf("not allowed to listen on %s; needed for %s", addr, purpose), hint)
	default:
		r.Add(diag.Fail, name, fmt.Sprintf("cannot listen on %s: %v", addr, err), "check the address format (host:port or :port)")
	}
}

func checkTCPRange(r *diag.Report, spec string) {
	lo, hi, err := parsePortRange(spec)
	if err != nil {
		r.Add(diag.Fail, "TCP tunnel ports", err.Error(), "use -tcp-ports START-END, for example 20000-29999")
		return
	}
	ln, lerr := net.Listen("tcp", ":"+strconv.Itoa(lo))
	if lerr != nil {
		r.Add(diag.Warn, "TCP tunnel ports", fmt.Sprintf("range %d-%d (%d ports), but the first port is not available: %v", lo, hi, hi-lo+1, lerr),
			"another program uses it; the server skips busy ports but tunnels may fail")
		return
	}
	ln.Close()
	r.Add(diag.OK, "TCP tunnel ports", fmt.Sprintf("range %d-%d (%d ports)", lo, hi, hi-lo+1), "")
}

func parsePortRange(spec string) (lo, hi int, err error) {
	a, b, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, fmt.Errorf("%q is not a range like 20000-29999", spec)
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("%q is not a valid port range (1-65535, start <= end)", spec)
	}
	return lo, hi, nil
}

// checkCertDir inspects the certificate directory and the domain secret
// without creating anything.
func checkCertDir(r *diag.Report, dir string) {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		parent := filepath.Dir(filepath.Clean(dir))
		if !writableDir(parent) {
			r.Add(diag.Fail, "Certificate dir", fmt.Sprintf("%s does not exist and %s is not writable", dir, parent), "create it or choose -cert-dir")
			return
		}
		r.Add(diag.OK, "Certificate dir", dir+" will be created on first start", "")
		return
	case err != nil:
		r.Add(diag.Fail, "Certificate dir", err.Error(), "check permissions")
		return
	case !info.IsDir():
		r.Add(diag.Fail, "Certificate dir", dir+" is not a directory", "choose another -cert-dir")
		return
	}
	if !writableDir(dir) {
		r.Add(diag.Fail, "Certificate dir", dir+" is not writable by this user", "fix the permissions: certificates, the ACME account key and the domain secret are stored here")
		return
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		r.Add(diag.Warn, "Certificate dir", fmt.Sprintf("%s is accessible by other users (mode %o)", dir, info.Mode().Perm()), "chmod 700 "+dir)
	} else {
		r.Add(diag.OK, "Certificate dir", dir+" is writable", "")
	}

	path := filepath.Join(dir, domainSecretFile)
	if _, err := readDomainSecret(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.Add(diag.OK, "Domain secret", "not created yet (created on first start; keys custom-domain DNS proofs)", "")
		} else {
			r.Add(diag.Fail, "Domain secret", err.Error(), "restore it from a backup; replacing it changes every published custom-domain TXT record")
		}
		return
	}
	if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		r.Add(diag.Warn, "Domain secret", fmt.Sprintf("%s is readable by other users (mode %o)", path, fi.Mode().Perm()), "chmod 600 "+path)
		return
	}
	r.Add(diag.OK, "Domain secret", "present and private", "")
}

func writableDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".wirerift-doctor-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return true
}

// checkCertificates reports expired or soon-to-expire certificates in the dir.
func checkCertificates(r *diag.Report, dir string) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
	if len(paths) == 0 {
		return
	}
	if len(paths) > maxCertsScan {
		paths = paths[:maxCertsScan]
	}
	var expired, soon, ok int
	var firstProblem string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		switch left := time.Until(cert.NotAfter); {
		case left <= 0:
			expired++
			if firstProblem == "" {
				firstProblem = filepath.Base(p)
			}
		case left < certWarnWindow:
			soon++
			if firstProblem == "" {
				firstProblem = filepath.Base(p)
			}
		default:
			ok++
		}
	}
	switch {
	case expired > 0:
		r.Add(diag.Fail, "Certificates", fmt.Sprintf("%d expired (for example %s), %d expiring soon, %d fine", expired, firstProblem, soon, ok),
			"expired certificates are replaced on the next handshake; check ACME logs if they are not")
	case soon > 0:
		r.Add(diag.Warn, "Certificates", fmt.Sprintf("%d expire within 14 days (for example %s), %d fine", soon, firstProblem, ok),
			"they are renewed automatically when ACME works; verify port 80 is reachable")
	default:
		r.Add(diag.OK, "Certificates", fmt.Sprintf("%d certificate(s), none expiring soon", ok), "")
	}
}

// checkWildcardDNS verifies that random subdomains of the base domain resolve,
// which every <name>.<domain> tunnel URL depends on.
func checkWildcardDNS(ctx context.Context, r *diag.Report, o doctorOptions) {
	d := strings.ToLower(o.Domain)
	if d == "localhost" || d == "test" || strings.HasSuffix(d, ".localhost") || strings.HasSuffix(d, ".test") {
		r.Add(diag.OK, "Wildcard DNS", d+" is a local-only name; no DNS records needed", "")
		return
	}
	lookup := o.lookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	probe := "wirerift-doctor-" + hex.EncodeToString(b) + "." + d

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := lookup(ctx, probe)
	if err != nil || len(addrs) == 0 {
		r.Add(diag.Warn, "Wildcard DNS", fmt.Sprintf("%s does not resolve", probe),
			fmt.Sprintf("add a wildcard record: *.%s  A  <this server's public IP> (tunnel URLs are <name>.%s)", d, d))
		return
	}
	r.Add(diag.OK, "Wildcard DNS", fmt.Sprintf("*.%s resolves (%s)", d, addrs[0]), "")
}

func checkLocalCA(r *diag.Report, dir string) {
	if dir == "" {
		var err error
		if dir, err = tlspkg.DefaultLocalCADir(); err != nil {
			return
		}
	}
	ca, err := tlspkg.LoadLocalCA(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.Add(diag.OK, "Local dev CA", "not created (only needed for -dev; created by `ca trust` or -dev)", "")
	case err != nil:
		r.Add(diag.Fail, "Local dev CA", err.Error(), "delete "+dir+" and run `wirerift-server ca trust` again")
	case time.Until(ca.Cert.NotAfter) < 30*24*time.Hour:
		r.Add(diag.Warn, "Local dev CA", "expires in less than 30 days", "recreate it: wirerift-server ca untrust -purge, then ca trust")
	case !tlspkg.IsTrustedBySystem(ca):
		r.Add(diag.Warn, "Local dev CA", "exists but this system does not trust it", "run: wirerift-server ca trust (only needed for -dev)")
	default:
		r.Add(diag.OK, "Local dev CA", "trusted by this system", "")
	}
}
