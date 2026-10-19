package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/server"
	tlspkg "github.com/wirerift/wirerift/internal/tls"
)

// fakeDNS is a TXT zone the test controls.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]string
	err     error
	asked   []string
}

func (d *fakeDNS) set(name string, values ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = values
}

func (d *fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, name)
	if d.err != nil {
		return nil, d.err
	}
	return d.records[name], nil
}

func newDomainEnv(t *testing.T) (*server.Server, func() *client.Client, *fakeDNS) {
	t.Helper()
	dns := &fakeDNS{records: map[string][]string{}}
	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.Domain = "tunnel.test"
	cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", authMgr
	cfg.DomainSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.TXTResolver = dns.lookup
	srv := server.New(cfg, nil)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	connect := func() *client.Client {
		cc := client.DefaultConfig()
		cc.ServerAddr, cc.Token, cc.Reconnect = srv.ControlAddr(), authMgr.DevToken(), false
		c := client.New(cc, nil)
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	return srv, connect, dns
}

var txtInstruction = regexp.MustCompile(`TXT record (\S+) with the value (wirerift-verification=[0-9a-f]+)`)

func edgeGet(t *testing.T, srv *server.Server, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+srv.HTTPAddr()+"/", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestCustomDomainFollowsTheInstructionsItGives(t *testing.T) {
	srv, connect, dns := newDomainEnv(t)
	c := connect()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello "+r.Host) }))
	defer local.Close()
	target := strings.TrimPrefix(local.URL, "http://")

	// 1) No DNS record yet: the error says exactly what to publish.
	_, err := c.HTTP(target, client.WithCustomDomain("App.Customer.org"))
	if err == nil {
		t.Fatal("tunnel created without any DNS proof")
	}
	m := txtInstruction.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("error does not tell the user which TXT record to create: %v", err)
	}
	name, value := m[1], m[2]
	if name != "_wirerift.app.customer.org" {
		t.Errorf("TXT name = %q (domain must be normalised to lowercase)", name)
	}
	if !strings.Contains(err.Error(), "CNAME to tunnel.test") {
		t.Errorf("error should say where to point the domain: %v", err)
	}

	// 2) A wrong value (e.g. the proof for another domain) is refused.
	dns.set(name, "wirerift-verification=00000000000000000000000000000000")
	if _, err := c.HTTP(target, client.WithCustomDomain("app.customer.org")); err == nil {
		t.Fatal("wrong TXT value accepted")
	}

	// 3) The user publishes the record exactly as instructed: it works.
	dns.set(name, "unrelated=1", value)
	tun, err := c.HTTP(target, client.WithCustomDomain("app.customer.org"), client.WithSubdomain("backup"))
	if err != nil {
		t.Fatalf("tunnel with correct DNS proof: %v", err)
	}
	if tun.PublicURL != "http://app.customer.org" {
		t.Errorf("PublicURL = %q", tun.PublicURL)
	}

	// 4) The edge routes the custom host (and still the normal subdomain).
	if code, body := edgeGet(t, srv, "app.customer.org"); code != 200 || body != "hello app.customer.org" {
		t.Errorf("custom host: %d %q", code, body)
	}
	if code, _ := edgeGet(t, srv, "APP.Customer.Org:8443"); code != 200 {
		t.Errorf("custom host with port/case: %d", code)
	}
	if code, _ := edgeGet(t, srv, "backup.tunnel.test"); code != 200 {
		t.Errorf("subdomain of the same tunnel: %d", code)
	}
	if !srv.IsCustomDomainActive("app.customer.org") || srv.IsCustomDomainActive("other.customer.org") {
		t.Error("IsCustomDomainActive wrong")
	}
	// Unknown foreign hosts are still refused.
	if code, _ := edgeGet(t, srv, "unknown.customer.org"); code != 400 {
		t.Errorf("unbound foreign host: %d, want 400", code)
	}

	// 5) Listing shows the domain exactly once (the alias key must not duplicate
	// the tunnel); closing frees it.
	var listed int
	for _, ti := range srv.ListTunnels() {
		if ti.CustomDomain == "app.customer.org" {
			listed++
		}
	}
	if listed != 1 {
		t.Errorf("ListTunnels shows the custom-domain tunnel %d times, want exactly 1", listed)
	}
	if n := len(srv.ListTunnels()); n != 1 {
		t.Errorf("ListTunnels has %d entries for one tunnel", n)
	}
	if n := srv.Stats()["active_tunnels"]; n != 1 {
		t.Errorf("active_tunnels = %v, want 1 (the alias key must not be counted)", n)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !srv.IsCustomDomainActive("app.customer.org") }, "domain released after close")
	if code, _ := edgeGet(t, srv, "app.customer.org"); code != 400 {
		t.Errorf("after close: %d, want 400", code)
	}
	if _, err := c.HTTP(target, client.WithCustomDomain("app.customer.org")); err != nil {
		t.Errorf("domain not reusable after close: %v", err)
	}
}

func TestCustomDomainCannotBeHijackedWhileInUse(t *testing.T) {
	_, connect, dns := newDomainEnv(t)
	c := connect()
	_, err := c.HTTP("localhost:1", client.WithCustomDomain("shop.customer.org"))
	m := txtInstruction.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatal(err)
	}
	dns.set(m[1], m[2])
	if _, err := c.HTTP("localhost:1", client.WithCustomDomain("shop.customer.org")); err != nil {
		t.Fatal(err)
	}

	// A second session, even with a valid proof, cannot take over the live domain.
	other := connect()
	if _, err := other.HTTP("localhost:2", client.WithCustomDomain("shop.customer.org")); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("hijack attempt err = %v, want 'already in use'", err)
	}
}

func TestCustomDomainValidation(t *testing.T) {
	_, connect, dns := newDomainEnv(t)
	c := connect()
	for domain, want := range map[string]string{
		"localhost":             "two labels",
		"tunnel.test":           "own domain",
		"app.tunnel.test":       "own domain",
		"*.customer.org":        "wildcards",
		"203.0.113.5":           "IP addresses",
		"bad_name.customer.org": "valid host name",
		"-x.customer.org":       "valid host name",
		"ünï.customer.org":      "ASCII",
	} {
		_, err := c.HTTP("localhost:1", client.WithCustomDomain(domain))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want mention of %q", domain, err, want)
		}
	}
	if len(dns.asked) != 0 {
		t.Errorf("invalid domains must not trigger DNS lookups: %v", dns.asked)
	}

	// TCP tunnels do not support custom domains: explicit error, not silently ignored.
	if _, err := c.TCP("localhost:1", 0, client.WithCustomDomain("app.customer.org")); err == nil || !strings.Contains(err.Error(), "only supported for HTTP") {
		t.Errorf("TCP custom domain err = %v", err)
	}

	// Lookup failures are reported as such.
	dns.mu.Lock()
	dns.err = errors.New("SERVFAIL")
	dns.mu.Unlock()
	if _, err := c.HTTP("localhost:1", client.WithCustomDomain("app.customer.org")); err == nil || !strings.Contains(err.Error(), "lookup failed") {
		t.Errorf("DNS error: %v", err)
	}
}

// The proof depends on the server secret: the same secret yields the same
// record after a restart; a different secret yields a different one.
func TestCustomDomainProofDependsOnPersistedSecret(t *testing.T) {
	record := func(secret string) string {
		cfg := server.DefaultConfig()
		cfg.ControlAddr, cfg.HTTPAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", auth.NewManager()
		cfg.DomainSecret = []byte(secret)
		cfg.TXTResolver = func(context.Context, string) ([]string, error) { return nil, nil }
		srv := server.New(cfg, nil)
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Stop()
		cc := client.DefaultConfig()
		cc.ServerAddr, cc.Token, cc.Reconnect = srv.ControlAddr(), cfg.AuthManager.DevToken(), false
		c := client.New(cc, nil)
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, err := c.HTTP("localhost:1", client.WithCustomDomain("app.customer.org"))
		m := txtInstruction.FindStringSubmatch(err.Error())
		if m == nil {
			t.Fatal(err)
		}
		return m[2]
	}
	a1 := record("secret-one-secret-one-secret-one!!")
	a2 := record("secret-one-secret-one-secret-one!!")
	b := record("secret-two-secret-two-secret-two!!")
	if a1 != a2 {
		t.Error("the proof changed across restarts with the same secret")
	}
	if a1 == b {
		t.Error("different secrets produced the same proof")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// Wiring of the TLS layer: a certificate is handed out for a custom domain only
// while a verified tunnel is serving it.
func TestCustomDomainCertificatesOnlyForLiveVerifiedDomains(t *testing.T) {
	mgr, err := tlspkg.NewManager(tlspkg.Config{Domain: "tunnel.test", CertDir: t.TempDir(), AutoCert: true})
	if err != nil {
		t.Fatal(err)
	}
	dns := &fakeDNS{records: map[string][]string{}}
	authMgr := auth.NewManager()
	cfg := server.DefaultConfig()
	cfg.Domain = "tunnel.test"
	cfg.ControlAddr, cfg.HTTPAddr, cfg.HTTPSAddr, cfg.AuthManager = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0", authMgr
	cfg.DomainSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.TXTResolver = dns.lookup
	cfg.TLSConfig = mgr.TLSConfig()
	srv := server.New(cfg, nil)
	mgr.SetHostAllower(srv.IsHostServed) // what cmd/wirerift-server does
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	handshake := func(sni string) error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", srv.HTTPSAddr(),
			&tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // self-signed test certs; only issuance is under test
		if err != nil {
			return err
		}
		return conn.Close()
	}

	// Not bound yet: no certificate for it, and none for arbitrary names.
	for _, sni := range []string{"app.customer.org", "random.example.net"} {
		if err := handshake(sni); err == nil {
			t.Errorf("a certificate was issued for %q without a verified tunnel", sni)
		}
	}
	// The base domain itself is always served; a subdomain only once a tunnel
	// registered it (nobody can force issuance for arbitrary subdomains).
	if err := handshake("tunnel.test"); err != nil {
		t.Errorf("base-domain handshake: %v", err)
	}
	if err := handshake("random123.tunnel.test"); err == nil {
		t.Error("a certificate was issued for a subdomain without a tunnel")
	}

	// Bind it (after a verified DNS proof): now the handshake succeeds.
	cc := client.DefaultConfig()
	cc.ServerAddr, cc.Token, cc.Reconnect = srv.ControlAddr(), authMgr.DevToken(), false
	c := client.New(cc, nil)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.HTTP("localhost:1", client.WithCustomDomain("app.customer.org"))
	m := txtInstruction.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatal(err)
	}
	dns.set(m[1], m[2])
	tun, err := c.HTTP("localhost:1", client.WithCustomDomain("app.customer.org"))
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake("app.customer.org"); err != nil {
		t.Errorf("verified, live custom domain gets no certificate: %v", err)
	}
	// A regular subdomain gets a certificate once its tunnel exists.
	if _, err := c.HTTP("localhost:1", client.WithSubdomain("live")); err != nil {
		t.Fatal(err)
	}
	if err := handshake("live.tunnel.test"); err != nil {
		t.Errorf("subdomain with a live tunnel gets no certificate: %v", err)
	}
	if err := handshake("other.customer.org"); err == nil {
		t.Error("another name under the same parent domain got a certificate")
	}

	// Closing the tunnel stops new certificates (a cached one may linger until expiry).
	_ = tun.Close()
	waitFor(t, func() bool { return !srv.IsCustomDomainActive("app.customer.org") }, "domain released")
	if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "brandnew.customer.org"}); err == nil {
		t.Error("certificate issued for an unbound name")
	}
}
