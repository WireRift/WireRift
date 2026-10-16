package tls

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type recorded struct {
	sudo bool
	cmd  string
}

// fakeTrust builds a Trust whose commands are recorded, not executed.
func fakeTrust(goos string, euid int, tools ...string) (*Trust, *[]recorded) {
	var log []recorded
	have := map[string]bool{}
	for _, t := range tools {
		have[t] = true
	}
	return &Trust{
		GOOS: goos,
		Home: "",
		EUID: euid,
		Run: func(sudo bool, name string, args ...string) error {
			log = append(log, recorded{sudo, strings.TrimSpace(name + " " + strings.Join(args, " "))})
			return nil
		},
		Look:      func(n string) bool { return have[n] },
		DirExists: func(string) bool { return false },
	}, &log
}

func cmds(log []recorded) []string {
	out := make([]string, 0, len(log))
	for _, r := range log {
		prefix := ""
		if r.sudo {
			prefix = "sudo "
		}
		out = append(out, prefix+r.cmd)
	}
	return out
}

func wantCmds(t *testing.T, log []recorded, want ...string) {
	t.Helper()
	got := cmds(log)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n got  %q\n want %q", got, want)
	}
}

func TestTrustInstallDebian(t *testing.T) {
	tr, log := fakeTrust("linux", 1000, "sudo", "update-ca-certificates")
	steps := tr.Install("/home/u/ca.pem")
	if len(steps) != 1 || !steps[0].OK() {
		t.Fatalf("steps = %+v", steps)
	}
	wantCmds(t, *log,
		"sudo install -D -m 0644 /home/u/ca.pem "+debianAnchor,
		"sudo update-ca-certificates")
}

func TestTrustInstallAsRootDoesNotUseSudo(t *testing.T) {
	tr, log := fakeTrust("linux", 0, "update-ca-certificates")
	tr.Install("/ca.pem")
	for _, r := range *log {
		if r.sudo {
			t.Errorf("root should not call sudo: %+v", r)
		}
	}
}

func TestTrustInstallRHELAndArch(t *testing.T) {
	tr, log := fakeTrust("linux", 0, "update-ca-trust")
	tr.DirExists = func(p string) bool { return p == filepath.Dir(archAnchor) } // Arch layout
	tr.Install("/ca.pem")
	wantCmds(t, *log, "install -D -m 0644 /ca.pem "+archAnchor, "update-ca-trust extract")

	tr, log = fakeTrust("linux", 0, "update-ca-trust")
	tr.Install("/ca.pem") // default: RHEL/Fedora
	wantCmds(t, *log, "install -D -m 0644 /ca.pem "+rhelAnchor, "update-ca-trust extract")
}

func TestTrustRemoveDebian(t *testing.T) {
	tr, log := fakeTrust("linux", 1000, "sudo", "update-ca-certificates")
	tr.Remove()
	wantCmds(t, *log, "sudo rm -f "+debianAnchor, "sudo update-ca-certificates --fresh")
}

func TestTrustDarwinAndWindows(t *testing.T) {
	tr, log := fakeTrust("darwin", 501, "sudo")
	tr.Install("/ca.pem")
	wantCmds(t, *log, "sudo security add-trusted-cert -d -r trustRoot -k "+macKeychain+" /ca.pem")

	tr, log = fakeTrust("windows", 0)
	tr.Install(`C:\ca.pem`)
	tr.Remove()
	wantCmds(t, *log,
		`certutil -addstore -f Root C:\ca.pem`,
		"certutil -delstore Root "+LocalCAName)
}

func TestTrustFailsClearlyWithoutSudoOrTool(t *testing.T) {
	tr, log := fakeTrust("linux", 1000, "update-ca-certificates") // no sudo
	steps := tr.Install("/ca.pem")
	if steps[0].Err == nil || !strings.Contains(steps[0].Err.Error(), "sudo") {
		t.Errorf("err = %v, want a sudo hint", steps[0].Err)
	}
	if len(*log) != 0 {
		t.Errorf("nothing should run without privileges: %v", cmds(*log))
	}

	tr, _ = fakeTrust("linux", 0) // no trust tool at all
	if steps := tr.Install("/ca.pem"); steps[0].Err == nil {
		t.Error("expected an error when no trust tool exists")
	}
	tr, _ = fakeTrust("plan9", 0)
	if steps := tr.Install("/ca.pem"); steps[0].Err == nil {
		t.Error("expected an error on unsupported OS")
	}
}

func TestTrustStopsOnFirstSystemError(t *testing.T) {
	tr, log := fakeTrust("linux", 0, "update-ca-certificates")
	boom := errors.New("boom")
	tr.Run = func(sudo bool, name string, args ...string) error {
		*log = append(*log, recorded{sudo, name})
		return boom
	}
	steps := tr.Install("/ca.pem")
	if !errors.Is(steps[0].Err, boom) {
		t.Fatalf("err = %v", steps[0].Err)
	}
	if len(*log) != 1 {
		t.Errorf("update-ca-certificates must not run after a failed copy: %v", cmds(*log))
	}
}

func TestTrustNSSBrowserDatabases(t *testing.T) {
	home := t.TempDir()
	for _, db := range []string{".pki/nssdb", ".mozilla/firefox/abc.default", "snap/firefox/common/.mozilla/firefox/x.profile"} {
		dir := filepath.Join(home, db)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cert9.db"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(home, ".mozilla/firefox/no-db.profile"), 0o755) // no cert9.db: ignored

	tr, log := fakeTrust("linux", 0, "update-ca-certificates", "certutil")
	tr.Home = home
	steps := tr.Install("/ca.pem")
	if len(steps) != 4 { // system + 3 databases
		t.Fatalf("steps = %d: %+v", len(steps), steps)
	}
	var adds, dels int
	for _, r := range *log {
		switch {
		case strings.Contains(r.cmd, "certutil") && strings.Contains(r.cmd, " -A "):
			adds++
			if r.sudo {
				t.Error("NSS changes are per-user and must not use sudo")
			}
			if !strings.Contains(r.cmd, `-t C,, -n `+LocalCAName) {
				t.Errorf("unexpected trust flags: %s", r.cmd)
			}
		case strings.Contains(r.cmd, "certutil") && strings.Contains(r.cmd, " -D "):
			dels++
		}
	}
	if adds != 3 || dels != 3 {
		t.Errorf("adds=%d dels=%d, want 3 and 3 (stale copy removed before adding)", adds, dels)
	}

	tr2, log2 := fakeTrust("linux", 0, "update-ca-certificates", "certutil")
	tr2.Home = home
	tr2.Remove()
	var removed int
	for _, r := range *log2 {
		if strings.Contains(r.cmd, "certutil") && strings.Contains(r.cmd, " -D ") {
			removed++
		}
	}
	if removed != 3 {
		t.Errorf("removed from %d databases, want 3", removed)
	}
}

func TestTrustNSSWithoutCertutilReportsHint(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".pki/nssdb"), 0o755)
	os.WriteFile(filepath.Join(home, ".pki/nssdb/cert9.db"), nil, 0o644)
	tr, _ := fakeTrust("linux", 0, "update-ca-certificates") // no certutil
	tr.Home = home
	steps := tr.Install("/ca.pem")
	last := steps[len(steps)-1]
	if last.OK() || !strings.Contains(last.Note, "libnss3-tools") {
		t.Errorf("want a skip note mentioning libnss3-tools, got %+v", last)
	}
}

func TestVerifyTrusted(t *testing.T) {
	ca := newTestCA(t)
	if err := VerifyTrusted(ca, ca.Pool()); err != nil {
		t.Errorf("CA should trust itself: %v", err)
	}
	if err := VerifyTrusted(ca, x509.NewCertPool()); err == nil {
		t.Error("an empty root pool must not trust the CA")
	}
	// The system store obviously does not contain a freshly created CA.
	if IsTrustedBySystem(ca) {
		t.Error("fresh CA reported as trusted by the system")
	}
}

func TestTrustRemoveOtherPlatforms(t *testing.T) {
	tr, log := fakeTrust("darwin", 501, "sudo")
	tr.Remove()
	wantCmds(t, *log, "sudo security delete-certificate -c "+LocalCAName+" "+macKeychain)

	tr, log = fakeTrust("linux", 0, "update-ca-trust")
	tr.Remove()
	wantCmds(t, *log, "rm -f "+rhelAnchor+" "+archAnchor, "update-ca-trust extract")

	tr, _ = fakeTrust("linux", 0)
	if s := tr.Remove(); s[0].Err == nil {
		t.Error("expected error without a trust tool")
	}
	tr, _ = fakeTrust("plan9", 0)
	if s := tr.Remove(); s[0].Err == nil {
		t.Error("expected error on unsupported OS")
	}

	// A failing first command stops the removal sequence.
	tr, log = fakeTrust("linux", 0, "update-ca-certificates")
	tr.Run = func(bool, string, ...string) error { return errors.New("denied") }
	if s := tr.Remove(); s[0].Err == nil {
		t.Error("expected the rm failure to surface")
	}
	_ = log
}

func TestTrustWindowsHasNoNSSStep(t *testing.T) {
	tr, _ := fakeTrust("windows", 0)
	tr.Home = t.TempDir()
	if steps := tr.Install(`C:\ca.pem`); len(steps) != 1 {
		t.Errorf("steps = %d, want just the Windows store", len(steps))
	}
}

func TestDefaultTrustAndRunCommand(t *testing.T) {
	tr := DefaultTrust()
	if tr.GOOS != runtime.GOOS || tr.Run == nil || tr.Look == nil || tr.DirExists == nil {
		t.Fatalf("DefaultTrust incomplete: %+v", tr)
	}
	if !tr.DirExists(t.TempDir()) || tr.DirExists("/definitely/not/here") {
		t.Error("DirExists wrong")
	}
	if tr.Look("definitely-not-a-real-binary-xyz") {
		t.Error("Look found a missing binary")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if !tr.Look("sh") {
		t.Skip("no sh")
	}
	if err := tr.Run(false, "sh", "-c", "exit 0"); err != nil {
		t.Errorf("successful command failed: %v", err)
	}
	err := tr.Run(false, "sh", "-c", "echo boom >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("failing command err = %v, want its output included", err)
	}
	if err := tr.Run(false, "sh", "-c", "exit 4"); err == nil {
		t.Error("exit status ignored")
	}
}

func TestSystemRunWithoutPrivilegesOrSudo(t *testing.T) {
	tr, _ := fakeTrust("linux", 1000, "update-ca-certificates") // not root, no sudo binary
	if err := tr.systemRun("true"); err == nil {
		t.Error("expected a privileges error")
	}
}
