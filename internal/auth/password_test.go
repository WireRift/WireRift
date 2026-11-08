package auth

import (
	"strings"
	"testing"
)

func TestPasswordHashAndCheck(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("a short password was accepted")
	}
	if _, err := HashPassword(strings.Repeat("x", 300)); err == nil {
		t.Error("a very long password was accepted")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "pbkdf2-sha256$") {
		t.Fatalf("hash: %q %v", h, err)
	}
	if strings.Contains(h, "correct") {
		t.Error("the hash leaks the password")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("two hashes of one password must differ (salt)")
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "correct horse batterY") || CheckPassword(h, "") {
		t.Error("password check wrong")
	}
	for _, bad := range []string{"", "x", "a$b$c$d", "pbkdf2-sha256$0$AA$AA", "pbkdf2-sha256$9999999999$AA$AA", "pbkdf2-sha256$1$!!$AA", "pbkdf2-sha256$1$AA$"} {
		if CheckPassword(bad, "whatever-password") {
			t.Errorf("garbage hash %q accepted", bad)
		}
	}
	if CheckPassword(h, strings.Repeat("x", 300)) {
		t.Error("over-long password accepted")
	}
	// RFC 7914 test vector for PBKDF2-HMAC-SHA256 (c=1).
	got := pbkdf2([]byte("passwd"), []byte("salt"), 1)
	if len(got) != 32 || got[0] != 0x55 || got[1] != 0xac || got[2] != 0x04 || got[3] != 0x6e {
		t.Errorf("pbkdf2 vector: %x", got)
	}
}

func TestVerifyPasswordAndSetPassword(t *testing.T) {
	f := &TokenFile{}
	yes := true
	if _, _, err := f.CreateToken(CreateOptions{Account: "Boss", Name: "t", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1, Admin: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.CreateToken(CreateOptions{Account: "nopass", Name: "t", MaxTunnels: -1, MaxSessions: -1, RateLimit: -1}); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPassword("boss", "a long enough password"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPassword("ghost", "a long enough password"); err == nil {
		t.Error("password for an unknown account")
	}
	if err := f.SetPassword("boss", "short"); err == nil {
		t.Error("weak password accepted")
	}
	m := NewManager("x")
	m.ApplyTokenFile(f)

	a, err := m.VerifyPassword(" BOSS ", "a long enough password")
	if err != nil || a.ID != "acct_boss" || !a.IsAdmin() {
		t.Fatalf("login: %+v %v", a, err)
	}
	for _, c := range [][2]string{{"boss", "wrong password!!"}, {"nopass", "a long enough password"}, {"ghost", "a long enough password"}, {"", ""}} {
		if _, err := m.VerifyPassword(c[0], c[1]); err != ErrBadLogin {
			t.Errorf("%v: %v", c, err)
		}
	}
	for i := range f.Accounts {
		f.Accounts[i].Active = false
	}
	m.ApplyTokenFile(f)
	if _, err := m.VerifyPassword("boss", "a long enough password"); err == nil {
		t.Error("an inactive account can log in")
	}
	if _, ok := m.AccountByID("acct_nope"); ok {
		t.Error("unknown account found")
	}
}
