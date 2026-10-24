package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

func runTokenCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runToken(args, &out)
	return out.String(), err
}

func TestTokenCreateListRevoke(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tokens.json")

	out, err := runTokenCmd(t, "create", "-file", file, "-account", "acme", "-name", "ci", "-max-tunnels", "4", "-expires", "30d")
	if err != nil {
		t.Fatal(err)
	}
	secret := regexp.MustCompile(`wr_[A-Za-z0-9]{40}`).FindString(out)
	idm := regexp.MustCompile(`tok_[a-z0-9]{8}`).FindString(out)
	if secret == "" || idm == "" {
		t.Fatalf("no secret/id in output:\n%s", out)
	}

	list, err := runTokenCmd(t, "list", "-file", file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(list, secret) {
		t.Error("list printed the secret")
	}
	for _, want := range []string{idm, "acme", "ci", "tunnels<=4", "active"} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q:\n%s", want, list)
		}
	}

	m := auth.NewManager("b")
	if n, err := m.LoadTokenFile(file); err != nil || n != 1 {
		t.Fatalf("load: %d %v", n, err)
	}
	if _, acct, err := m.ValidateToken(secret); err != nil || acct.MaxTunnels != 4 {
		t.Fatalf("created token does not validate: %v %v", acct, err)
	}

	if _, err := runTokenCmd(t, "revoke", "-file", file, idm); err != nil {
		t.Fatal(err)
	}
	m.LoadTokenFile(file)
	if _, _, err := m.ValidateToken(secret); err == nil {
		t.Error("revoked token still validates")
	}
	if list, _ := runTokenCmd(t, "list", "-file", file); !strings.Contains(list, "revoked") {
		t.Errorf("list does not show revoked:\n%s", list)
	}
}

func TestTokenCommandErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tokens.json")
	for name, args := range map[string][]string{
		"no account":     {"create", "-file", file},
		"bad account":    {"create", "-file", file, "-account", "bad name"},
		"bad expires":    {"create", "-file", file, "-account", "a", "-expires", "soon"},
		"negative":       {"create", "-file", file, "-account", "a", "-max-tunnels", "-5"},
		"revoke no id":   {"revoke", "-file", file},
		"revoke unknown": {"revoke", "-file", file, "tok_nope"},
		"unknown":        {"frobnicate"},
	} {
		if _, err := runTokenCmd(t, args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if out, err := runTokenCmd(t); err != nil || !strings.Contains(out, "Usage") {
		t.Errorf("no args should print usage, got %q %v", out, err)
	}
	if out, _ := runTokenCmd(t, "list", "-file", file); !strings.Contains(out, "No tokens") {
		t.Errorf("empty list: %q", out)
	}
}

func TestTokenFilePathDefaults(t *testing.T) {
	if got := tokenFilePath("", "certs"); got != filepath.Join("certs", "tokens.json") {
		t.Errorf("default = %q", got)
	}
	if got := tokenFilePath("x.json", "certs"); got != "x.json" {
		t.Errorf("explicit = %q", got)
	}
}

func TestParseLifetime(t *testing.T) {
	for in, want := range map[string]time.Duration{"90m": 90 * time.Minute, "2d": 48 * time.Hour, "12h": 12 * time.Hour} {
		if got, err := parseLifetime(in); err != nil || got != want {
			t.Errorf("parseLifetime(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "-1d", "xd", "-3h", "abc"} {
		if _, err := parseLifetime(bad); err == nil {
			t.Errorf("parseLifetime(%q) accepted", bad)
		}
	}
}

func TestLoadTokenFileAtStartup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	file := filepath.Join(t.TempDir(), "tokens.json")
	m := auth.NewManager("b")

	if err := loadTokenFile(m, file, logger); err != nil {
		t.Fatalf("a missing file must be fine: %v", err)
	}
	if _, err := runTokenCmd(t, "create", "-file", file, "-account", "a"); err != nil {
		t.Fatal(err)
	}
	if err := loadTokenFile(m, file, logger); err != nil {
		t.Fatal(err)
	}
	// A corrupt file must stop the server from starting rather than silently
	// running without the tokens people expect to work.
	if err := os.WriteFile(file, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadTokenFile(m, file, logger); err == nil {
		t.Error("a corrupt token file was ignored")
	}
}

func TestRunSubcommandDispatch(t *testing.T) {
	if handled, _ := runSubcommand(nil); handled {
		t.Error("no args is not a subcommand")
	}
	if handled, _ := runSubcommand([]string{"-dev"}); handled {
		t.Error("a flag is not a subcommand")
	}
	if handled, err := runSubcommand([]string{"token", "help"}); !handled || err != nil {
		t.Errorf("token help: handled=%v err=%v", handled, err)
	}
}
