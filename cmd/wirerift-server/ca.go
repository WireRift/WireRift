package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	tlspkg "github.com/wirerift/wirerift/internal/tls"
)

const caUsage = `Manage the local development CA used by -dev mode.

Usage:
  wirerift-server ca <command> [-ca-dir DIR]

Commands:
  status    Show the CA and whether this machine trusts it
  trust     Create the CA if needed and install it in the system and browser
            trust stores (asks for sudo once; changes can be undone with untrust)
  untrust   Remove the CA from those stores (-purge also deletes its files)
  path      Print the CA certificate path (creating the CA if needed)
`

// runCA implements "wirerift-server ca <command>".
func runCA(args []string, out io.Writer, trust *tlspkg.Trust) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, caUsage)
		return nil
	}
	cmd := args[0]

	fs := flag.NewFlagSet("ca "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	caDirFlag := fs.String("ca-dir", "", "CA directory (default: per-user config dir)")
	purge := fs.Bool("purge", false, "delete the CA files after untrusting")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("ca %s: %v", cmd, err)
	}
	dir, err := resolveCADir(*caDirFlag)
	if err != nil {
		return err
	}

	switch cmd {
	case "path":
		ca, err := tlspkg.LoadOrCreateLocalCA(dir)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, ca.CertPath())
		return nil

	case "status":
		return caStatus(dir, out)

	case "trust":
		if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" && *caDirFlag == "" {
			fmt.Fprintf(out, "Note: running as root through sudo, so the CA is stored in root's config directory and\n"+
				"your browsers' certificate databases are not touched. Run it without sudo (it asks for sudo itself).\n\n")
		}
		ca, err := tlspkg.LoadOrCreateLocalCA(dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Local CA: %s\n", ca.CertPath())
		fmt.Fprintf(out, "It can only issue certificates for %s and loopback IPs, so it cannot be\n", permittedNames())
		fmt.Fprintln(out, "used to impersonate real websites even if its key leaks.")
		fmt.Fprintln(out)
		steps := trust.Install(ca.CertPath())
		printSteps(out, steps)
		if len(steps) > 0 && steps[0].Err != nil {
			return errors.New("could not install the CA in the system trust store")
		}
		if tlspkg.IsTrustedBySystem(ca) {
			fmt.Fprintln(out, "\nDone. Restart your browser if it was open.")
		} else {
			fmt.Fprintln(out, "\nInstalled, but this process does not see the CA as trusted yet (some systems need a new login or a browser restart).")
		}
		return nil

	case "untrust":
		steps := trust.Remove()
		printSteps(out, steps)
		failed := len(steps) > 0 && steps[0].Err != nil
		if *purge && !failed {
			if err := purgeCAFiles(dir); err != nil {
				return fmt.Errorf("delete the CA files in %s: %v", dir, err)
			}
			fmt.Fprintf(out, "Deleted the CA files in %s\n", dir)
		}
		if failed {
			return errors.New("could not remove the CA from the system trust store")
		}
		return nil
	}
	return fmt.Errorf("unknown ca command %q\n\n%s", cmd, caUsage)
}

func resolveCADir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return tlspkg.DefaultLocalCADir()
}

func permittedNames() string { return ".localhost and .test" }

func caStatus(dir string, out io.Writer) error {
	ca, err := tlspkg.LoadLocalCA(dir)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(out, "No local CA at %s yet.\n", dir)
		fmt.Fprintln(out, "It is created by `wirerift-server -dev` or `wirerift-server ca trust`.")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Directory:   %s\n", dir)
	fmt.Fprintf(out, "Certificate: %s\n", ca.CertPath())
	fmt.Fprintf(out, "Subject:     %s\n", ca.Cert.Subject.CommonName)
	fmt.Fprintf(out, "Expires:     %s\n", ca.Cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(out, "SHA-256:     %s\n", ca.Fingerprint())
	fmt.Fprintf(out, "Names:       %s (+ loopback IPs only)\n", permittedNames())
	for _, w := range ca.Legacy() {
		fmt.Fprintf(out, "Warning:     created by an older version, %s; recreate it with `ca untrust -purge` then `ca trust`\n", w)
	}
	if tlspkg.IsTrustedBySystem(ca) {
		fmt.Fprintln(out, "System:      trusted")
	} else {
		fmt.Fprintln(out, "System:      NOT trusted; run `wirerift-server ca trust`")
	}
	return nil
}

func printSteps(out io.Writer, steps []tlspkg.TrustStep) {
	for _, s := range steps {
		switch {
		case s.Err != nil:
			fmt.Fprintf(out, "  ✗ %s: %v\n", s.Target, s.Err)
		case s.Note != "":
			fmt.Fprintf(out, "  ! %s: %s\n", s.Target, s.Note)
		default:
			fmt.Fprintf(out, "  ✓ %s\n", s.Target)
		}
	}
	if len(steps) == 0 {
		fmt.Fprintln(out, "  (nothing to do)")
	}
}

// purgeCAFiles deletes only the files the CA itself created (never the whole
// directory: -ca-dir is user supplied and may hold anything), then removes the
// directory if that left it empty.
func purgeCAFiles(dir string) error {
	for _, name := range []string{"rootCA.pem", "rootCA-key.pem", ".create.lock"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(leftovers) > 0 {
		for _, p := range leftovers {
			_ = os.Remove(p)
		}
	}
	_ = os.Remove(dir) // only succeeds when empty
	return nil
}
