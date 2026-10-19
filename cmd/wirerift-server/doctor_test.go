package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/diag"
)

func newReport() (*diag.Report, *bytes.Buffer) {
	var out bytes.Buffer
	return &diag.Report{Out: &out}, &out
}

func TestCheckPort(t *testing.T) {
	r, out := newReport()
	checkPort(r, "X", "127.0.0.1:0", "testing")
	if r.Failures != 0 || !strings.Contains(out.String(), "is free") {
		t.Errorf("free port: %s", out.String())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r, out = newReport()
	checkPort(r, "X", ln.Addr().String(), "the control plane")
	if r.Failures != 1 || !strings.Contains(out.String(), "already in use") || !strings.Contains(out.String(), "the control plane") {
		t.Errorf("busy port: %s", out.String())
	}

	r, out = newReport()
	checkPort(r, "X", "not-an-address", "testing")
	if r.Failures != 1 || !strings.Contains(out.String(), "address format") {
		t.Errorf("bad address: %s", out.String())
	}

	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		if data, _ := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start"); strings.TrimSpace(string(data)) != "0" {
			r, out = newReport()
			checkPort(r, "X", ":80", "the HTTP edge")
			if r.Failures != 1 || !strings.Contains(out.String(), "setcap") {
				t.Errorf("privileged port: %s", out.String())
			}
		}
	}
}

func TestParsePortRange(t *testing.T) {
	ok := map[string][2]int{"20000-29999": {20000, 29999}, " 1 - 65535 ": {1, 65535}, "5-5": {5, 5}}
	for in, want := range ok {
		lo, hi, err := parsePortRange(in)
		if err != nil || lo != want[0] || hi != want[1] {
			t.Errorf("%q: %d-%d %v", in, lo, hi, err)
		}
	}
	for _, in := range []string{"", "20000", "a-b", "0-10", "10-70000", "30-20", "1-2-3"} {
		if _, _, err := parsePortRange(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestCheckTCPRange(t *testing.T) {
	r, out := newReport()
	checkTCPRange(r, "47000-47010")
	if r.Failures+r.Warnings != 0 || !strings.Contains(out.String(), "11 ports") {
		t.Errorf("valid range: %s", out.String())
	}
	r, _ = newReport()
	checkTCPRange(r, "garbage")
	if r.Failures != 1 {
		t.Error("garbage range accepted")
	}
	ln, _ := net.Listen("tcp", ":0")
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	r, out = newReport()
	checkTCPRange(r, strconv.Itoa(port)+"-"+strconv.Itoa(port+5))
	if r.Warnings != 1 || !strings.Contains(out.String(), "first port is not available") {
		t.Errorf("busy first port: %s", out.String())
	}
}

func TestCheckCertDir(t *testing.T) {
	base := t.TempDir()

	// Missing directory: reported, nothing created.
	missing := filepath.Join(base, "new", "certs")
	r, out := newReport()
	checkCertDir(r, filepath.Join(base, "certs"))
	if r.Failures != 0 || !strings.Contains(out.String(), "will be created") {
		t.Errorf("missing dir: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(base, "certs")); err == nil {
		t.Error("doctor created the certificate directory")
	}
	r, out = newReport()
	checkCertDir(r, missing) // parent does not exist either
	if r.Failures != 1 {
		t.Errorf("unwritable parent: %s", out.String())
	}

	// A file instead of a directory.
	file := filepath.Join(base, "afile")
	os.WriteFile(file, nil, 0o600)
	r, out = newReport()
	checkCertDir(r, file)
	if r.Failures != 1 || !strings.Contains(out.String(), "not a directory") {
		t.Errorf("file: %s", out.String())
	}

	// Healthy private directory without a secret yet.
	dir := filepath.Join(base, "private")
	os.Mkdir(dir, 0o700)
	r, out = newReport()
	checkCertDir(r, dir)
	if r.Failures+r.Warnings != 0 || !strings.Contains(out.String(), "not created yet") {
		t.Errorf("healthy dir: %s", out.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("doctor left files behind: %v", entries)
	}

	if runtime.GOOS == "windows" {
		return
	}
	// Loose permissions are warned about.
	loose := filepath.Join(base, "loose")
	os.Mkdir(loose, 0o755)
	os.Chmod(loose, 0o755)
	r, out = newReport()
	checkCertDir(r, loose)
	if r.Warnings != 1 || !strings.Contains(out.String(), "chmod 700") {
		t.Errorf("loose dir: %s", out.String())
	}

	// Secret: good / world-readable / corrupt.
	if _, err := loadOrCreateDomainSecret(dir); err != nil {
		t.Fatal(err)
	}
	r, out = newReport()
	checkCertDir(r, dir)
	if r.Failures+r.Warnings != 0 || !strings.Contains(out.String(), "present and private") {
		t.Errorf("good secret: %s", out.String())
	}
	secretPath := filepath.Join(dir, domainSecretFile)
	os.Chmod(secretPath, 0o644)
	r, out = newReport()
	checkCertDir(r, dir)
	if r.Warnings != 1 || !strings.Contains(out.String(), "chmod 600") {
		t.Errorf("loose secret: %s", out.String())
	}
	os.WriteFile(secretPath, []byte("corrupt"), 0o600)
	r, out = newReport()
	checkCertDir(r, dir)
	if r.Failures != 1 || !strings.Contains(out.String(), "corrupt") {
		t.Errorf("corrupt secret: %s", out.String())
	}
	if got, _ := os.ReadFile(secretPath); string(got) != "corrupt" {
		t.Error("doctor modified the secret")
	}
}

func writeTestCert(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCertificates(t *testing.T) {
	dir := t.TempDir()
	r, out := newReport()
	checkCertificates(r, dir) // nothing there: silent
	if out.Len() != 0 {
		t.Errorf("empty dir printed %q", out.String())
	}

	writeTestCert(t, dir, "fine.example.com", time.Now().Add(60*24*time.Hour))
	os.WriteFile(filepath.Join(dir, "junk.crt"), []byte("not pem"), 0o600)
	r, out = newReport()
	checkCertificates(r, dir)
	if r.Failures+r.Warnings != 0 || !strings.Contains(out.String(), "1 certificate") {
		t.Errorf("healthy: %s", out.String())
	}

	writeTestCert(t, dir, "soon.example.com", time.Now().Add(3*24*time.Hour))
	r, out = newReport()
	checkCertificates(r, dir)
	if r.Warnings != 1 || !strings.Contains(out.String(), "soon.example.com") {
		t.Errorf("expiring: %s", out.String())
	}

	writeTestCert(t, dir, "dead.example.com", time.Now().Add(-24*time.Hour))
	r, out = newReport()
	checkCertificates(r, dir)
	if r.Failures != 1 || !strings.Contains(out.String(), "1 expired") {
		t.Errorf("expired: %s", out.String())
	}
}

func TestCheckWildcardDNS(t *testing.T) {
	var asked string
	resolves := func(_ context.Context, host string) ([]string, error) {
		asked = host
		return []string{"203.0.113.9"}, nil
	}
	fails := func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }

	r, out := newReport()
	checkWildcardDNS(context.Background(), r, doctorOptions{Domain: "Tunnel.Example.com", lookupHost: resolves})
	if r.Warnings != 0 || !strings.HasPrefix(asked, "wirerift-doctor-") || !strings.HasSuffix(asked, ".tunnel.example.com") {
		t.Errorf("probe %q: %s", asked, out.String())
	}

	r, out = newReport()
	checkWildcardDNS(context.Background(), r, doctorOptions{Domain: "tunnel.example.com", lookupHost: fails})
	if r.Warnings != 1 || !strings.Contains(out.String(), "*.tunnel.example.com") {
		t.Errorf("missing wildcard: %s", out.String())
	}

	asked = ""
	for _, d := range []string{"localhost", "myapp.test", "x.localhost"} {
		r, _ = newReport()
		checkWildcardDNS(context.Background(), r, doctorOptions{Domain: d, lookupHost: resolves})
		if asked != "" || r.Warnings != 0 {
			t.Errorf("local-only domain %q triggered a lookup", d)
		}
	}
}

func TestCheckLocalCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	r, out := newReport()
	checkLocalCA(r, dir)
	if r.Failures+r.Warnings != 0 || !strings.Contains(out.String(), "not created") {
		t.Errorf("no CA: %s", out.String())
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("doctor created the CA")
	}

	var buf bytes.Buffer
	if err := runCA([]string{"path", "-ca-dir", dir}, &buf, nil); err != nil {
		t.Fatal(err)
	}
	r, out = newReport()
	checkLocalCA(r, dir)
	if r.Warnings != 1 || !strings.Contains(out.String(), "does not trust") {
		t.Errorf("untrusted CA: %s", out.String())
	}

	os.WriteFile(filepath.Join(dir, "rootCA.pem"), []byte("x"), 0o644)
	r, out = newReport()
	checkLocalCA(r, dir)
	if r.Failures != 1 {
		t.Errorf("corrupt CA: %s", out.String())
	}
}

func TestRunServerDoctor(t *testing.T) {
	free := func() string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		return ln.Addr().String()
	}
	_, dashPort, _ := net.SplitHostPort(free())
	t.Setenv("WIRERIFT_DOMAIN", "")
	args := []string{
		"-control", free(), "-http", free(), "-https", free(),
		"-dashboard-port", dashPort, "-domain", "myapp.test", "-tcp-ports", "47100-47110",
		"-cert-dir", filepath.Join(t.TempDir(), "certs"), "-ca-dir", filepath.Join(t.TempDir(), "ca"),
	}
	var out bytes.Buffer
	if err := runServerDoctor(args, &out); err != nil {
		t.Fatalf("healthy configuration reported problems: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "All checks passed.") {
		t.Errorf("output:\n%s", out.String())
	}

	// A busy port makes the command fail.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	bad := append([]string{}, args...)
	bad[1] = ln.Addr().String()
	out.Reset()
	err := runServerDoctor(bad, &out)
	if err == nil || !strings.Contains(err.Error(), "problem") || !strings.Contains(out.String(), "already in use") {
		t.Errorf("busy control port: %v\n%s", err, out.String())
	}

	if err := runServerDoctor([]string{"-bogus"}, &out); err == nil {
		t.Error("unknown flag accepted")
	}
	if err := run(context.Background(), []string{"doctor", "-bogus"}); err == nil {
		t.Error("run(doctor) did not route to the doctor")
	}
}

func TestDoctorWarnsAboutExposedDashboardAndAcmePort(t *testing.T) {
	var out bytes.Buffer
	failures := runServerChecks(context.Background(), &out, doctorOptions{
		Domain: "myapp.test", Control: "127.0.0.1:0", HTTP: "127.0.0.1:0", HTTPS: "127.0.0.1:0",
		DashboardBind: "0.0.0.0", DashboardPort: 0, TCPRange: "47200-47210",
		CertDir: filepath.Join(t.TempDir(), "c"), CADir: filepath.Join(t.TempDir(), "ca"),
		ACMEEmail: "me@example.com",
	})
	if failures != 0 {
		t.Fatalf("failures=%d\n%s", failures, out.String())
	}
	for _, want := range []string{"plain HTTP", "Let's Encrypt", "port 80"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing warning %q:\n%s", want, out.String())
		}
	}
}

func TestDoctorEnvironmentFallbacks(t *testing.T) {
	t.Setenv("WIRERIFT_DOMAIN", "env.localhost")
	var out bytes.Buffer
	_ = runServerDoctor([]string{"-control", "127.0.0.1:0", "-http", "127.0.0.1:0", "-https", "127.0.0.1:0",
		"-dashboard-port", "0", "-tcp-ports", "47300-47310", "-cert-dir", filepath.Join(t.TempDir(), "c"), "-ca-dir", filepath.Join(t.TempDir(), "ca")}, &out)
	if !strings.Contains(out.String(), "domain env.localhost") {
		t.Errorf("WIRERIFT_DOMAIN ignored:\n%s", out.String())
	}
}

func TestDoctorFlagsWinOverEnvironment(t *testing.T) {
	t.Setenv("WIRERIFT_DOMAIN", "env.localhost")
	var out bytes.Buffer
	_ = runServerDoctor([]string{"-domain", "flag.localhost", "-control", "127.0.0.1:0", "-http", "127.0.0.1:0", "-https", "127.0.0.1:0",
		"-dashboard-port", "0", "-tcp-ports", "47400-47410", "-cert-dir", filepath.Join(t.TempDir(), "c"), "-ca-dir", filepath.Join(t.TempDir(), "ca")}, &out)
	if !strings.Contains(out.String(), "domain flag.localhost") || strings.Contains(out.String(), "env.localhost") {
		t.Errorf("the flag must win over WIRERIFT_DOMAIN:\n%s", out.String())
	}
}

// Windows reports Winsock error numbers rather than Go's portable errno values;
// both spellings must be classified the same way.
func TestBindErrorClassification(t *testing.T) {
	wrap := func(e syscall.Errno) error { return &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", e)} }
	for name, tc := range map[string]struct {
		err        error
		inUse, den bool
	}{
		"portable EADDRINUSE": {wrap(syscall.EADDRINUSE), true, false},
		"WSAEADDRINUSE":       {wrap(wsaeAddrUse), true, false},
		"portable EACCES":     {wrap(syscall.EACCES), false, true},
		"WSAEACCES":           {wrap(wsaeAccess), false, true},
		"something else":      {errors.New("boom"), false, false},
	} {
		if isAddrInUse(tc.err) != tc.inUse || isBindDenied(tc.err) != tc.den {
			t.Errorf("%s: inUse=%v denied=%v, want %v/%v", name, isAddrInUse(tc.err), isBindDenied(tc.err), tc.inUse, tc.den)
		}
	}
}
