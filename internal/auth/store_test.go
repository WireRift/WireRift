package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newOpts(account string) CreateOptions {
	return CreateOptions{Account: account, Name: "t", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1}
}

func TestTokenFileRoundTripStoresOnlyDigests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "tokens.json")
	f, err := LoadTokenFile(path)
	if err != nil || len(f.Tokens) != 0 {
		t.Fatalf("missing file: %v %v", f, err)
	}

	o := newOpts("Acme")
	o.MaxTunnels, o.MaxSessions, o.RateLimit = 3, 2, 50
	secret, tok, err := f.CreateToken(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, TokenPrefix) || len(secret) != len(TokenPrefix)+40 {
		t.Errorf("unexpected secret shape %q", secret)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secret) {
		t.Fatal("the plaintext secret was written to disk")
	}
	if !strings.Contains(string(raw), tok.Hash) {
		t.Error("the digest is not stored")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}

	g, err := LoadTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := g.Account("acct_acme")
	if !ok || a.MaxTunnels != 3 || a.MaxSessions != 2 || a.RateLimit != 50 || !a.Active {
		t.Errorf("account not preserved: %+v", a)
	}
}

func TestCreateTokenValidationAndAccountReuse(t *testing.T) {
	f := &TokenFile{}
	for _, bad := range []string{"", "-x", "has space", "dev_account", "Dev_Account", strings.Repeat("a", 41)} {
		if _, _, err := f.CreateToken(newOpts(bad)); err == nil {
			t.Errorf("account %q accepted", bad)
		}
	}

	o := newOpts("team")
	o.MaxTunnels = 5
	if _, _, err := f.CreateToken(o); err != nil {
		t.Fatal(err)
	}
	// A second token for the account keeps the limits it did not restate.
	if _, _, err := f.CreateToken(newOpts("TEAM")); err != nil {
		t.Fatal(err)
	}
	if len(f.Accounts) != 1 || len(f.Tokens) != 2 || f.Accounts[0].MaxTunnels != 5 {
		t.Errorf("accounts=%+v tokens=%d", f.Accounts, len(f.Tokens))
	}
}

func TestRevokeUnknownToken(t *testing.T) {
	f := &TokenFile{}
	if err := f.Revoke("tok_nope"); err == nil {
		t.Fatal("revoking an unknown token succeeded")
	}
}

func TestManagerValidatesFileTokens(t *testing.T) {
	m := NewManager("bootstrap-secret")
	f := &TokenFile{}

	live, liveTok, _ := f.CreateToken(newOpts("live"))
	revoked, revokedTok, _ := f.CreateToken(newOpts("gone"))
	_ = f.Revoke(revokedTok.ID)
	expiring := newOpts("exp")
	expiring.Expires = time.Hour
	expired, expTok, _ := f.CreateToken(expiring)
	past := time.Now().Add(-time.Minute)
	for i := range f.Tokens {
		if f.Tokens[i].ID == expTok.ID {
			f.Tokens[i].ExpiresAt = &past
		}
	}
	inactive, _, _ := f.CreateToken(newOpts("off"))
	for i := range f.Accounts {
		if f.Accounts[i].ID == "acct_off" {
			f.Accounts[i].Active = false
		}
	}
	m.ApplyTokenFile(f)

	tok, acct, err := m.ValidateToken(live)
	if err != nil || tok.ID != liveTok.ID || acct.ID != "acct_live" {
		t.Fatalf("live token: %v %v %v", tok, acct, err)
	}
	for name, secret := range map[string]string{"revoked": revoked, "expired": expired, "inactive account": inactive, "garbage": "wr_nope", "empty": ""} {
		if _, _, err := m.ValidateToken(secret); err == nil {
			t.Errorf("%s token was accepted", name)
		}
	}
	if _, acct, err := m.ValidateToken("bootstrap-secret"); err != nil || acct.ID != DevAccountID {
		t.Errorf("bootstrap token broke: %v %v", acct, err)
	}
}

func TestReloadRevokesAndForgetsOldAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	f := &TokenFile{}
	secret, tok, _ := f.CreateToken(newOpts("a"))
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}

	m := NewManager("b")
	if n, err := m.LoadTokenFile(path); err != nil || n != 1 {
		t.Fatalf("load: %d %v", n, err)
	}
	if _, _, err := m.ValidateToken(secret); err != nil {
		t.Fatal(err)
	}

	_ = f.Revoke(tok.ID)
	_ = f.Save(path)
	if _, err := m.LoadTokenFile(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.ValidateToken(secret); err == nil {
		t.Error("revoked token still valid after reload")
	}

	// A broken file leaves the loaded state alone.
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := m.LoadTokenFile(path); err == nil {
		t.Error("a corrupt file must be an error")
	}

	// Removing the file drops every file token and account.
	_ = os.Remove(path)
	if _, err := m.LoadTokenFile(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.accounts.Load("acct_a"); ok {
		t.Error("account from the old file is still loaded")
	}
}

func TestFileCannotRedefineBootstrapAccount(t *testing.T) {
	m := NewManager("b")
	m.ApplyTokenFile(&TokenFile{
		Accounts: []FileAccount{{ID: DevAccountID, Active: true, MaxTunnels: 1}},
		Tokens:   []FileToken{{ID: "tok_x", AccountID: DevAccountID, Hash: HashSecret("x")}},
	})
	if _, _, err := m.ValidateToken("x"); err == nil {
		t.Error("a file token tied to the bootstrap account was accepted")
	}
	if a, _ := m.accounts.Load(DevAccountID); a.(*Account).MaxTunnels != 100 {
		t.Error("bootstrap account was overwritten")
	}
}

func TestSavedFileIsValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	f := &TokenFile{}
	_, _, _ = f.CreateToken(newOpts("x"))
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !json.Valid(raw) {
		t.Fatal("not valid JSON")
	}
}

func TestStillValidFollowsTheTokenFile(t *testing.T) {
	m := NewManager()
	tf := &TokenFile{}
	secret, rec, err := tf.CreateToken(CreateOptions{Account: "acme", Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	m.ApplyTokenFile(tf)
	tok, _, err := m.ValidateToken(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !m.StillValid(tok) {
		t.Fatal("a fresh token must be valid")
	}
	if !m.StillValid(nil) {
		t.Error("a session without a recorded token is left alone")
	}
	dev, _, _ := m.ValidateToken(m.DevToken())
	if !m.StillValid(dev) {
		t.Error("the bootstrap token stays valid")
	}

	// Reloading a file that revoked it makes the old handle invalid, even though
	// the reload produced new Token objects.
	if err := tf.Revoke(rec.ID); err != nil {
		t.Fatal(err)
	}
	m.ApplyTokenFile(tf)
	if m.StillValid(tok) {
		t.Error("a revoked token is still valid")
	}

	// Dropping the token from the file, or its account, has the same effect.
	tf2 := &TokenFile{}
	s2, _, _ := tf2.CreateToken(CreateOptions{Account: "acme", Name: "b"})
	m.ApplyTokenFile(tf2)
	tok2, _, err := m.ValidateToken(s2)
	if err != nil {
		t.Fatal(err)
	}
	m.ApplyTokenFile(&TokenFile{})
	if m.StillValid(tok2) {
		t.Error("a token removed from the file is still valid")
	}
}
