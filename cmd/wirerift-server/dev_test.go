package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tlspkg "github.com/wirerift/wirerift/internal/tls"
)

func devOpts(t *testing.T, explicit map[string]bool) (devOptions, *string, *string, *string, *string) {
	t.Helper()
	domain, control, httpA, httpsA := "wirerift.com", ":4443", ":80", ":443"
	return devOptions{
		Domain: &domain, Control: &control, HTTP: &httpA, HTTPS: &httpsA,
		Explicit: explicit, CADir: filepath.Join(t.TempDir(), "ca"),
	}, &domain, &control, &httpA, &httpsA
}

func TestSetupDevAppliesDefaults(t *testing.T) {
	o, domain, control, httpA, httpsA := devOpts(t, map[string]bool{})
	dev, err := setupDev(o)
	if err != nil {
		t.Fatal(err)
	}
	if *domain != "localhost" || *control != "127.0.0.1:4443" || *httpA != "127.0.0.1:8080" || *httpsA != "127.0.0.1:8443" {
		t.Errorf("defaults: domain=%s control=%s http=%s https=%s", *domain, *control, *httpA, *httpsA)
	}
	if dev.Port != 8443 {
		t.Errorf("port = %d", dev.Port)
	}
	// Loopback only: -dev must never default to listening on all interfaces.
	for _, a := range []string{*control, *httpA, *httpsA} {
		if !strings.HasPrefix(a, "127.0.0.1:") {
			t.Errorf("dev address %q is not loopback", a)
		}
	}
}

func TestSetupDevKeepsExplicitChoices(t *testing.T) {
	o, domain, _, httpA, httpsA := devOpts(t, map[string]bool{"domain": true, "http": true, "https": true})
	*domain, *httpA, *httpsA = "myapp.test", "127.0.0.1:9000", "127.0.0.1:9443"
	dev, err := setupDev(o)
	if err != nil {
		t.Fatal(err)
	}
	if *domain != "myapp.test" || *httpA != "127.0.0.1:9000" || dev.Port != 9443 {
		t.Errorf("explicit values were overridden: %s %s %d", *domain, *httpA, dev.Port)
	}
}

func TestSetupDevRejectsUnsafeInput(t *testing.T) {
	for _, d := range []string{"example.com", "tunnel.mycompany.io", "127.0.0.1"} {
		o, domain, _, _, _ := devOpts(t, map[string]bool{"domain": true})
		*domain = d
		if _, err := setupDev(o); err == nil {
			t.Errorf("domain %q accepted in dev mode", d)
		}
	}
	o, _, _, _, _ := devOpts(t, map[string]bool{})
	o.ACMEEmail = "me@example.com"
	if _, err := setupDev(o); err == nil {
		t.Error("-dev with -acme-email accepted")
	}
}

// End to end: an HTTPS server using the dev provider is trusted by a client
// that trusts only the local CA, for any subdomain, and refuses nothing else.
func TestDevProviderServesTrustedHTTPS(t *testing.T) {
	o, _, _, _, _ := devOpts(t, map[string]bool{})
	dev, err := setupDev(o)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello ", r.Host)
	}))
	srv.TLS = dev.Provider.TLSConfig()
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	get := func(host string, roots *x509.CertPool) (string, error) {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}, Timeout: 5 * time.Second}
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}

	for _, host := range []string{"localhost", "myapp.localhost", "other.localhost"} {
		got, err := get(host, dev.CA.Pool())
		if err != nil || !strings.HasPrefix(got, "hello ") {
			t.Errorf("%s: %q, %v", host, got, err)
		}
	}
	if _, err := get("myapp.localhost", x509.NewCertPool()); err == nil {
		t.Error("a client that does not trust the local CA accepted the certificate")
	}
}

func TestCACommandStatusPathAndTrust(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	var out bytes.Buffer

	// No CA yet: status must not create one.
	if err := runCA([]string{"status", "-ca-dir", dir}, &out, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No local CA") {
		t.Errorf("status output: %s", out.String())
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("status created the CA directory")
	}

	// path creates it and prints the certificate path.
	out.Reset()
	if err := runCA([]string{"path", "-ca-dir", dir}, &out, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != filepath.Join(dir, "rootCA.pem") {
		t.Errorf("path = %q", got)
	}

	// trust runs the injected commands (no real system change) and reports.
	var ran []string
	tr := &tlspkg.Trust{
		GOOS: "linux", EUID: 0,
		Run:       func(_ bool, name string, args ...string) error { ran = append(ran, name); return nil },
		Look:      func(n string) bool { return n == "update-ca-certificates" },
		DirExists: func(string) bool { return false },
	}
	out.Reset()
	if err := runCA([]string{"trust", "-ca-dir", dir}, &out, tr); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, ",") != "install,update-ca-certificates" {
		t.Errorf("commands = %v", ran)
	}
	if !strings.Contains(out.String(), "✓ system") || !strings.Contains(out.String(), "cannot be") {
		t.Errorf("trust output: %s", out.String())
	}

	// untrust -purge removes the files only when the system step succeeded.
	out.Reset()
	if err := runCA([]string{"untrust", "-purge", "-ca-dir", dir}, &out, tr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("-purge did not delete the CA directory")
	}

	// A failing system step is an error and must not purge.
	_ = os.MkdirAll(dir, 0o700)
	bad := *tr
	bad.Run = func(bool, string, ...string) error { return fmt.Errorf("denied") }
	if err := runCA([]string{"untrust", "-purge", "-ca-dir", dir}, &out, &bad); err == nil {
		t.Error("expected an error when the system step fails")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("CA directory was purged despite a failed untrust")
	}
}

func TestCACommandUsageAndUnknown(t *testing.T) {
	var out bytes.Buffer
	if err := runCA(nil, &out, nil); err != nil || !strings.Contains(out.String(), "Usage:") {
		t.Errorf("usage: %v %q", err, out.String())
	}
	if err := runCA([]string{"bogus"}, &out, nil); err == nil {
		t.Error("unknown command accepted")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// run -dev end to end: the HTTPS edge answers with a certificate that a client
// trusting only the local CA accepts, and tunnel URLs would use https + port.
func TestRunDevModeServesTrustedHTTPS(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "ca")
	httpsAddr := freeAddr(t)
	_, dashPort, _ := net.SplitHostPort(freeAddr(t))

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{
			"-dev", "-ca-dir", caDir,
			"-control", freeAddr(t), "-http", freeAddr(t), "-https", httpsAddr,
			"-dashboard-port", dashPort, "-tcp-ports", "30300-30310",
		})
	}()

	var ca *tlspkg.LocalCA
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if ca, err = tlspkg.LoadLocalCA(caDir); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ca == nil {
		t.Fatal("dev mode did not create the local CA")
	}

	var resp *http.Response
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "app.localhost"},
	}}
	for time.Now().Before(deadline) {
		var err error
		req, _ := http.NewRequest(http.MethodGet, "https://"+httpsAddr+"/", nil)
		req.Host = "app.localhost"
		if resp, err = client.Do(req); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("HTTPS edge never became reachable with the local CA trusted")
	}
	resp.Body.Close()
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Subject.CommonName != "app.localhost" {
		t.Errorf("served certificate: %+v", resp.TLS)
	}
	// "No tunnel registered" is a 502; the point is the TLS layer works.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d", resp.StatusCode)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

func TestRunDevModeRejectsBadDomain(t *testing.T) {
	err := run(context.Background(), []string{"-dev", "-ca-dir", t.TempDir(), "-domain", "example.com"})
	if err == nil || !strings.Contains(err.Error(), ".localhost or .test") {
		t.Errorf("err = %v", err)
	}
}

func TestRunDispatchesCASubcommand(t *testing.T) {
	// "ca" is routed before flag parsing; `path` creates the CA in -ca-dir.
	dir := filepath.Join(t.TempDir(), "ca")
	if err := run(context.Background(), []string{"ca", "path", "-ca-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rootCA.pem")); err != nil {
		t.Error(err)
	}
}

func TestCAStatusForExistingCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	var out bytes.Buffer
	if err := runCA([]string{"path", "-ca-dir", dir}, &out, nil); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runCA([]string{"status", "-ca-dir", dir}, &out, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"WireRift Local Development CA", "SHA-256:", ".localhost and .test", "NOT trusted"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status output missing %q:\n%s", want, out.String())
		}
	}
	// Corrupt CA: status reports the problem instead of replacing it.
	os.WriteFile(filepath.Join(dir, "rootCA.pem"), []byte("x"), 0o644)
	if err := runCA([]string{"status", "-ca-dir", dir}, &out, nil); err == nil {
		t.Error("corrupt CA not reported")
	}
}

func TestCATrustReportsFailureAndNotes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	tr := &tlspkg.Trust{
		GOOS: "linux", EUID: 0,
		Run:       func(bool, string, ...string) error { return fmt.Errorf("denied") },
		Look:      func(n string) bool { return n == "update-ca-certificates" },
		DirExists: func(string) bool { return false },
	}
	var out bytes.Buffer
	if err := runCA([]string{"trust", "-ca-dir", dir}, &out, tr); err == nil {
		t.Error("trust must fail when the system step fails")
	}
	if !strings.Contains(out.String(), "✗") {
		t.Errorf("failure not shown: %s", out.String())
	}
	if err := runCA([]string{"trust", "-bogusflag"}, &out, tr); err == nil {
		t.Error("bad flag accepted")
	}

	// printSteps variants: a note and an empty list.
	out.Reset()
	printSteps(&out, []tlspkg.TrustStep{{Target: "browsers", Note: "install certutil"}})
	printSteps(&out, nil)
	if !strings.Contains(out.String(), "! browsers: install certutil") || !strings.Contains(out.String(), "nothing to do") {
		t.Errorf("printSteps output: %q", out.String())
	}
}

func TestExplicitSettingsIncludesEnvironment(t *testing.T) {
	t.Setenv("WIRERIFT_DOMAIN", "a.localhost")
	t.Setenv("WIRERIFT_CONTROL_ADDR", "127.0.0.1:1")
	t.Setenv("WIRERIFT_HTTP_ADDR", "127.0.0.1:2")
	got := explicitSettings(map[string]bool{"https": true})
	for _, k := range []string{"domain", "control", "http", "https"} {
		if !got[k] {
			t.Errorf("%s not marked explicit", k)
		}
	}
}

func TestDevBannerLines(t *testing.T) {
	var out bytes.Buffer
	(*devSetup)(nil).printBanner(&out, ":443", "localhost")
	if out.Len() != 0 {
		t.Errorf("nil devSetup printed %q", out.String())
	}
	o, _, _, _, _ := devOpts(t, map[string]bool{})
	dev, err := setupDev(o)
	if err != nil {
		t.Fatal(err)
	}
	dev.printBanner(&out, "127.0.0.1:8443", "localhost")
	for _, want := range []string{"HTTPS:", "https://<name>.localhost:8443", "Local CA:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("banner missing %q: %s", want, out.String())
		}
	}
}
