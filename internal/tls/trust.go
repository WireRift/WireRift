package tls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// TrustStep is the outcome for one trust store.
type TrustStep struct {
	Target string // human readable store, e.g. "system (update-ca-certificates)"
	Err    error  // nil on success
	Note   string // extra hint when skipped or partially done
}

// OK reports whether the step succeeded.
func (s TrustStep) OK() bool { return s.Err == nil && s.Note == "" }

// Trust installs and removes the development CA in the operating system and
// browser trust stores. Every external effect goes through Run/Look, so tests
// can verify the exact commands without touching the machine.
type Trust struct {
	GOOS string
	Home string
	EUID int

	// Run executes a command; with sudo it must elevate (and may prompt).
	Run func(sudo bool, name string, args ...string) error
	// Look reports whether an executable is on PATH.
	Look func(name string) bool
	// DirExists reports whether a directory exists.
	DirExists func(path string) bool
}

// DefaultTrust returns a Trust that acts on the real machine.
func DefaultTrust() *Trust {
	home, _ := os.UserHomeDir()
	return &Trust{
		GOOS: runtime.GOOS,
		Home: home,
		EUID: os.Geteuid(),
		Run:  runCommand,
		Look: func(name string) bool { _, err := exec.LookPath(name); return err == nil },
		DirExists: func(p string) bool {
			info, err := os.Stat(p)
			return err == nil && info.IsDir()
		},
	}
}

func runCommand(sudo bool, name string, args ...string) error {
	var cmd *exec.Cmd
	var out bytes.Buffer
	if sudo {
		cmd = exec.Command("sudo", append([]string{name}, args...)...) //nolint:gosec // callers pass fixed command names and CA paths we generated
		// Attach the terminal so sudo can ask for a password.
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	} else {
		cmd = exec.Command(name, args...) //nolint:gosec // callers pass fixed command names and CA paths we generated
		cmd.Stdout, cmd.Stderr = &out, &out
	}
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(out.String()); msg != "" {
			return fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

const goosWindows = "windows"

const (
	debianAnchor = "/usr/local/share/ca-certificates/wirerift-local-ca.crt"
	rhelAnchor   = "/etc/pki/ca-trust/source/anchors/wirerift-local-ca.crt"
	archAnchor   = "/etc/ca-certificates/trust-source/anchors/wirerift-local-ca.crt"
	macKeychain  = "/Library/Keychains/System.keychain"
)

// needsSudo reports whether system-store commands must be elevated.
func (t *Trust) needsSudo() bool { return t.GOOS != goosWindows && t.EUID != 0 }

func (t *Trust) systemRun(name string, args ...string) error {
	sudo := t.needsSudo()
	if sudo && !t.Look("sudo") {
		return errors.New("root privileges are required and sudo was not found; re-run as root")
	}
	return t.Run(sudo, name, args...)
}

// Install adds the CA at caPath to the system store and to every browser NSS
// database found. It never aborts early: each store reports its own result.
func (t *Trust) Install(caPath string) []TrustStep {
	steps := []TrustStep{t.installSystem(caPath)}
	steps = append(steps, t.nss(caPath, true)...)
	return steps
}

// Remove deletes the CA from the same stores.
func (t *Trust) Remove() []TrustStep {
	steps := []TrustStep{t.removeSystem()}
	steps = append(steps, t.nss("", false)...)
	return steps
}

func (t *Trust) installSystem(caPath string) TrustStep {
	switch t.GOOS {
	case "linux":
		switch {
		case t.Look("update-ca-certificates"):
			step := TrustStep{Target: "system (update-ca-certificates)"}
			if err := t.systemRun("install", "-D", "-m", "0644", caPath, debianAnchor); err != nil {
				step.Err = err
				return step
			}
			step.Err = t.systemRun("update-ca-certificates")
			return step
		case t.Look("update-ca-trust"):
			anchor := rhelAnchor
			if !t.DirExists(filepath.Dir(rhelAnchor)) && t.DirExists(filepath.Dir(archAnchor)) {
				anchor = archAnchor
			}
			step := TrustStep{Target: "system (update-ca-trust)"}
			if err := t.systemRun("install", "-D", "-m", "0644", caPath, anchor); err != nil {
				step.Err = err
				return step
			}
			step.Err = t.systemRun("update-ca-trust", "extract")
			return step
		}
		return TrustStep{Target: "system", Err: errors.New("no supported trust tool found (need update-ca-certificates or update-ca-trust)")}
	case "darwin":
		return TrustStep{Target: "system (macOS keychain)", Err: t.systemRun(
			"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", macKeychain, caPath)}
	case goosWindows:
		return TrustStep{Target: "system (Windows Root store)", Err: t.systemRun("certutil", "-addstore", "-f", "Root", caPath)}
	}
	return TrustStep{Target: "system", Err: fmt.Errorf("unsupported OS %q", t.GOOS)}
}

func (t *Trust) removeSystem() TrustStep {
	switch t.GOOS {
	case "linux":
		switch {
		case t.Look("update-ca-certificates"):
			step := TrustStep{Target: "system (update-ca-certificates)"}
			if err := t.systemRun("rm", "-f", debianAnchor); err != nil {
				step.Err = err
				return step
			}
			step.Err = t.systemRun("update-ca-certificates", "--fresh")
			return step
		case t.Look("update-ca-trust"):
			step := TrustStep{Target: "system (update-ca-trust)"}
			if err := t.systemRun("rm", "-f", rhelAnchor, archAnchor); err != nil {
				step.Err = err
				return step
			}
			step.Err = t.systemRun("update-ca-trust", "extract")
			return step
		}
		return TrustStep{Target: "system", Err: errors.New("no supported trust tool found")}
	case "darwin":
		return TrustStep{Target: "system (macOS keychain)", Err: t.systemRun(
			"security", "delete-certificate", "-c", LocalCAName, macKeychain)}
	case goosWindows:
		return TrustStep{Target: "system (Windows Root store)", Err: t.systemRun("certutil", "-delstore", "Root", LocalCAName)}
	}
	return TrustStep{Target: "system", Err: fmt.Errorf("unsupported OS %q", t.GOOS)}
}

// nssDBs lists browser certificate databases (Chrome/Chromium on Linux and
// Firefox profiles), which do not read the system store on Linux.
func (t *Trust) nssDBs() []string {
	if t.Home == "" {
		return nil
	}
	var dirs []string
	add := func(dir string) {
		if _, err := os.Stat(filepath.Join(dir, "cert9.db")); err == nil {
			dirs = append(dirs, dir)
		}
	}
	add(filepath.Join(t.Home, ".pki", "nssdb"))
	for _, pattern := range []string{
		filepath.Join(t.Home, ".mozilla", "firefox", "*"),
		filepath.Join(t.Home, "snap", "firefox", "common", ".mozilla", "firefox", "*"),
		filepath.Join(t.Home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox", "*"),
		filepath.Join(t.Home, "Library", "Application Support", "Firefox", "Profiles", "*"),
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			add(m)
		}
	}
	return dirs
}

func (t *Trust) nss(caPath string, install bool) []TrustStep {
	if t.GOOS == goosWindows {
		return nil // browsers use the Windows store
	}
	dbs := t.nssDBs()
	if len(dbs) == 0 {
		return nil
	}
	if !t.Look("certutil") {
		return []TrustStep{{
			Target: "browsers (Chrome/Firefox NSS)",
			Note:   fmt.Sprintf("%d browser certificate database(s) found but `certutil` is missing; install libnss3-tools (Debian/Ubuntu) or nss-tools (Fedora/Arch), then run this again", len(dbs)),
		}}
	}
	steps := make([]TrustStep, 0, len(dbs))
	for _, db := range dbs {
		step := TrustStep{Target: "browser database " + db}
		if install {
			// Replace any stale copy first so re-running is idempotent.
			_ = t.Run(false, "certutil", "-d", "sql:"+db, "-D", "-n", LocalCAName)
			step.Err = t.Run(false, "certutil", "-d", "sql:"+db, "-A", "-t", "C,,", "-n", LocalCAName, "-i", caPath)
		} else {
			step.Err = t.Run(false, "certutil", "-d", "sql:"+db, "-D", "-n", LocalCAName)
		}
		steps = append(steps, step)
	}
	return steps
}

// VerifyTrusted reports whether certificates from ca are accepted by roots
// (nil = the operating system's trust store). It issues a probe certificate
// and verifies it exactly the way a client would.
func VerifyTrusted(ca *LocalCA, roots *x509.CertPool) error {
	probe, err := ca.IssueLeaf([]string{"trust-check.localhost"})
	if err != nil {
		return err
	}
	_, err = probe.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "trust-check.localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// IsTrustedBySystem reports whether the operating system trusts ca.
func IsTrustedBySystem(ca *LocalCA) bool { return VerifyTrusted(ca, nil) == nil }
