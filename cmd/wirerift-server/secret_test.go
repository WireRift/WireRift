package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/server"
)

func TestLoadOrCreateDomainSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	first, err := loadOrCreateDomainSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 {
		t.Fatalf("secret too short: %d bytes", len(first))
	}
	second, err := loadOrCreateDomainSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("secret changed between loads: published DNS proofs would break after a restart")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(dir, domainSecretFile))
		if info.Mode().Perm() != 0o600 {
			t.Errorf("secret file mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

func TestLoadDomainSecretRefusesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, domainSecretFile)
	for _, content := range []string{"not hex at all", "abcd"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadOrCreateDomainSecret(dir)
		if err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("content %q: err = %v, want a corrupt-file error (never silently replaced)", content, err)
		}
		if got, _ := os.ReadFile(path); string(got) != content {
			t.Errorf("corrupt secret was overwritten")
		}
	}
}

func TestLoadDomainSecretUnwritableDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(file, nil, 0o600)
	if _, err := loadOrCreateDomainSecret(filepath.Join(file, "sub")); err == nil {
		t.Error("expected an error when the directory cannot be created")
	}
}

func TestHTTPSPort(t *testing.T) {
	for addr, want := range map[string]int{":443": 0, "0.0.0.0:443": 0, ":8443": 8443, "127.0.0.1:9443": 9443, "garbage": 0, ":notaport": 0} {
		if got := httpsPort(addr); got != want {
			t.Errorf("httpsPort(%q) = %d, want %d", addr, got, want)
		}
	}
}

func TestTXTResolverFor(t *testing.T) {
	if r, err := txtResolverFor(""); r != nil || err != nil {
		t.Errorf("empty address should mean the system resolver, got %v %v", r, err)
	}
	for _, addr := range []string{"1.1.1.1", "1.1.1.1:5353", "[::1]:53", "::1", "dns.example.net"} {
		if r, err := txtResolverFor(addr); r == nil || err != nil {
			t.Errorf("%q: %v %v", addr, r, err)
		}
	}
	if _, err := txtResolverFor(":53"); err == nil {
		t.Error("an address without a host was accepted")
	}
}

// The resolver really talks to the DNS server it was given.
func TestTXTResolverAsksTheConfiguredServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	asked := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Decode the QNAME, answer with one TXT record.
		var labels []string
		for i := 12; i < n && buf[i] != 0; i += int(buf[i]) + 1 {
			labels = append(labels, string(buf[i+1:i+1+int(buf[i])]))
		}
		asked <- strings.Join(labels, ".")
		end := 12
		for buf[end] != 0 {
			end += int(buf[end]) + 1
		}
		question := buf[12 : end+5]
		txt := []byte("wirerift-verification=abc")
		rdata := append([]byte{byte(len(txt))}, txt...)
		resp := append([]byte{buf[0], buf[1], 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0}, question...)
		resp = append(resp, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0, 0, byte(len(rdata)))
		resp = append(resp, rdata...)
		pc.WriteTo(resp, addr)
	}()

	resolve, err := txtResolverFor(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := resolve(ctx, "_wirerift.app.example.com")
	if err != nil || len(got) != 1 || got[0] != "wirerift-verification=abc" {
		t.Fatalf("got %v, %v", got, err)
	}
	if q := <-asked; q != "_wirerift.app.example.com" {
		t.Errorf("DNS server was asked for %q", q)
	}
}

func TestConfigureCustomDomains(t *testing.T) {
	cfg := server.DefaultConfig()
	if err := configureCustomDomains(&cfg, nil, filepath.Join(t.TempDir(), "certs"), "", ":443"); err != nil {
		t.Fatal(err)
	}
	if len(cfg.DomainSecret) < 32 || cfg.TXTResolver != nil || cfg.PublicScheme != "" {
		t.Errorf("config = secret %d bytes, resolver %v, scheme %q", len(cfg.DomainSecret), cfg.TXTResolver, cfg.PublicScheme)
	}
	if err := configureCustomDomains(&cfg, nil, t.TempDir(), "1.1.1.1", ":443"); err != nil || cfg.TXTResolver == nil {
		t.Errorf("dns server not applied: %v", err)
	}
	if err := configureCustomDomains(&cfg, nil, t.TempDir(), ":53", ":443"); err == nil {
		t.Error("invalid -dns-server accepted")
	}
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, domainSecretFile), []byte("corrupt"), 0o600)
	if err := configureCustomDomains(&cfg, nil, bad, "", ":443"); err == nil {
		t.Error("corrupt secret accepted")
	}
}

func TestTokenBanner(t *testing.T) {
	t.Setenv("WIRERIFT_TOKEN", "")
	t.Setenv("WIRERIFT_TOKEN_FILE", "")
	if tokenSourceLabel("") != "random" || tokenSourceLabel("x") != "-token flag" {
		t.Error("tokenSourceLabel")
	}
	t.Setenv("WIRERIFT_TOKEN", "from-env")
	if tokenSourceLabel("") != "WIRERIFT_TOKEN env" {
		t.Error("env label")
	}

	var out strings.Builder
	if shown := printToken(&out, "random", "generated-secret"); shown != "generated-secret" || !strings.Contains(out.String(), "generated-secret") {
		t.Errorf("random token must be shown: %q / %q", shown, out.String())
	}
	out.Reset()
	if shown := printToken(&out, "-token flag", "operator-secret"); shown != "<your token>" || strings.Contains(out.String(), "operator-secret") {
		t.Errorf("operator token leaked into the banner: %q / %q", shown, out.String())
	}
}

func TestResolveBootstrapTokenFromSecretFile(t *testing.T) {
	t.Setenv("WIRERIFT_TOKEN", "")
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WIRERIFT_TOKEN_FILE", path)

	token, source, err := resolveBootstrapToken("")
	if err != nil {
		t.Fatal(err)
	}
	if token != "file-secret" || source != "WIRERIFT_TOKEN_FILE secret" {
		t.Fatalf("token/source = %q/%q", token, source)
	}

	t.Setenv("WIRERIFT_TOKEN", "env-secret")
	if token, source, err = resolveBootstrapToken(""); err != nil || token != "env-secret" || source != "WIRERIFT_TOKEN env" {
		t.Fatalf("env precedence = %q/%q/%v", token, source, err)
	}
	if token, source, err = resolveBootstrapToken("flag-secret"); err != nil || token != "flag-secret" || source != "-token flag" {
		t.Fatalf("flag precedence = %q/%q/%v", token, source, err)
	}
}

func TestResolveBootstrapTokenSecretFileFailsClosed(t *testing.T) {
	t.Setenv("WIRERIFT_TOKEN", "")
	for name, prepare := range map[string]func(t *testing.T) string{
		"missing": func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
		"empty": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "empty")
			if err := os.WriteFile(path, []byte(" \n"), 0600); err != nil {
				t.Fatal(err)
			}
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("WIRERIFT_TOKEN_FILE", prepare(t))
			if _, _, err := resolveBootstrapToken(""); err == nil {
				t.Fatal("invalid secret file silently fell back to a random token")
			}
		})
	}
}

// Racing first starts must agree on one secret, and no partial file may ever
// be observable (a reader used to be able to see an empty file and refuse to start).
func TestDomainSecretCreationIsAtomicAndRaceSafe(t *testing.T) {
	for i := 0; i < 100; i++ {
		dir := filepath.Join(t.TempDir(), "certs")
		const workers = 6
		secrets := make([][]byte, workers)
		errs := make([]error, workers)
		done := make(chan struct{})
		for w := 0; w < workers; w++ {
			go func(w int) {
				secrets[w], errs[w] = loadOrCreateDomainSecret(dir)
				done <- struct{}{}
			}(w)
		}
		for w := 0; w < workers; w++ {
			<-done
		}
		for w := 0; w < workers; w++ {
			if errs[w] != nil {
				t.Fatalf("iteration %d worker %d: %v", i, w, errs[w])
			}
			if string(secrets[w]) != string(secrets[0]) {
				t.Fatalf("iteration %d: processes disagree about the secret", i)
			}
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("iteration %d: leftover files: %v", i, entries)
		}
	}
}

func TestEmptySecretFileLeftByACrashIsHealed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, domainSecretFile)
	os.WriteFile(path, nil, 0o600) // what an interrupted older version left behind
	secret, err := loadOrCreateDomainSecret(dir)
	if err != nil || len(secret) < 32 {
		t.Fatalf("empty file not healed: %v", err)
	}
	if again, _ := loadOrCreateDomainSecret(dir); string(again) != string(secret) {
		t.Error("the healed secret is not stable")
	}
}

func TestPrintTokenDisabled(t *testing.T) {
	var out strings.Builder
	if shown := printToken(&out, "disabled", "dev_whatever"); shown != "<your token>" || strings.Contains(out.String(), "dev_whatever") {
		t.Errorf("disabled token leaked or wrong placeholder: %q / %q", shown, out.String())
	}
}

func TestDropRandomBootstrap(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tokens.json")
	m := auth.NewManager()
	secret := m.DevToken()
	// No token file tokens: the random token stays.
	if got := dropRandomBootstrap(m, "random"); got != "random" {
		t.Fatalf("source = %q, want random", got)
	}
	if _, _, err := m.ValidateToken(secret); err != nil {
		t.Fatalf("random token should still work: %v", err)
	}
	// With file tokens it is dropped, and an operator-supplied one never is.
	if _, err := runTokenCmd(t, "create", "-file", file, "-account", "acct"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.LoadTokenFile(file); err != nil {
		t.Fatal(err)
	}
	if got := dropRandomBootstrap(m, "-token flag"); got != "-token flag" {
		t.Errorf("operator token source changed to %q", got)
	}
	if got := dropRandomBootstrap(m, "random"); got != "disabled" {
		t.Fatalf("source = %q, want disabled", got)
	}
	if _, _, err := m.ValidateToken(secret); err == nil {
		t.Error("random token still valid after being dropped")
	}
}

func TestSetEdgeRate(t *testing.T) {
	var cfg server.Config
	if err := setEdgeRate(&cfg, 250, 40); err != nil || cfg.EdgeRatePerIP != 250 || cfg.EdgeRateBurst != 40 {
		t.Fatalf("setEdgeRate = %v, cfg %+v", err, cfg)
	}
	if err := setEdgeRate(&cfg, 0, 0); err != nil {
		t.Errorf("zero (defaults) rejected: %v", err)
	}
	if setEdgeRate(&cfg, -1, 0) == nil || setEdgeRate(&cfg, 0, -1) == nil {
		t.Error("negative values accepted")
	}
}

func TestDashboardHostName(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "dashboard": "dashboard.t.example", " Admin ": "admin.t.example", "ops.example.org": "ops.example.org",
	} {
		if got := dashboardHostName(in, "t.example"); got != want {
			t.Errorf("dashboardHostName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublishDashboardNeedsHTTPS(t *testing.T) {
	srv := server.New(server.DefaultConfig(), nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := publishDashboard(srv, nil, "", "t.example", false, logger); err != nil {
		t.Errorf("unset flag must be a no-op: %v", err)
	}
	if err := publishDashboard(srv, nil, "dashboard", "t.example", false, logger); err == nil {
		t.Error("publishing without HTTPS must be refused")
	}
}
