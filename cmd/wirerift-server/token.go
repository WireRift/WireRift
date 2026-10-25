package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
)

const usageText = `Usage: wirerift-server token <command> [options]

Manage the access tokens stored in the token file (default <cert-dir>/tokens.json).
The server reads the file at startup (restart it to apply changes).

Commands:
  create    Create a token (the secret is shown once)
  list      List tokens
  revoke    Revoke a token by its id

Options (all commands):
  -file path       token file (default <cert-dir>/tokens.json)
  -cert-dir dir    certificate directory, as for the server (default "certs")

create options:
  -account name    account the token belongs to (created if new; required)
  -name label      a label for this token
  -max-tunnels N   tunnels the account may have at once, over all its
                   connections (0 = only the per-connection cap)
  -max-sessions N  simultaneous connections of the account (0 = unlimited)
  -rate N          tunnel creations per second for the account (0 = default)
  -expires dur     lifetime, e.g. 12h or 30d (default: never)
`

// tokenFilePath is where the token file lives: -file, else <cert-dir>/tokens.json.
func tokenFilePath(file, certDir string) string {
	if file != "" {
		return file
	}
	return filepath.Join(certDir, "tokens.json")
}

// runToken implements "wirerift-server token ...".
func runToken(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, usageText)
		return nil
	}
	cmd := args[0]

	fs := flag.NewFlagSet("token "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", "", "")
	certDir := fs.String("cert-dir", "certs", "")
	account := fs.String("account", "", "")
	name := fs.String("name", "", "")
	maxTunnels := fs.Int("max-tunnels", -1, "")
	maxSessions := fs.Int("max-sessions", -1, "")
	rate := fs.Int("rate", -1, "")
	expires := fs.String("expires", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("token %s: %v\n\n%s", cmd, err, usageText)
	}
	path := tokenFilePath(*file, *certDir)

	switch cmd {
	case "create":
		return tokenCreate(path, out, auth.CreateOptions{
			Account: *account, Name: *name, MaxTunnels: *maxTunnels, MaxSessions: *maxSessions, RateLimit: *rate,
		}, *expires)
	case "list":
		return tokenList(path, out)
	case "revoke":
		if fs.NArg() != 1 {
			return fmt.Errorf("token revoke: give the token id (see 'token list')")
		}
		return tokenRevoke(path, out, fs.Arg(0))
	default:
		return fmt.Errorf("unknown token command %q\n\n%s", cmd, usageText)
	}
}

func tokenCreate(path string, out io.Writer, o auth.CreateOptions, expires string) error {
	if o.Account == "" {
		return fmt.Errorf("token create: -account is required")
	}
	for flagName, v := range map[string]int{"max-tunnels": o.MaxTunnels, "max-sessions": o.MaxSessions, "rate": o.RateLimit} {
		if v < -1 {
			return fmt.Errorf("token create: -%s must not be negative", flagName)
		}
	}
	if expires != "" {
		d, err := parseLifetime(expires)
		if err != nil {
			return fmt.Errorf("token create: -expires: %v", err)
		}
		o.Expires = d
	}
	f, err := auth.LoadTokenFile(path)
	if err != nil {
		return err
	}
	secret, tok, err := f.CreateToken(o)
	if err != nil {
		return fmt.Errorf("token create: %w", err)
	}
	if err := f.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(out, "Token %s created for account %q.\n\n  %s\n\n", tok.ID, o.Account, secret)
	fmt.Fprintln(out, "Copy it now: only a digest is stored and the secret cannot be shown again.")
	return nil
}

func tokenList(path string, out io.Writer) error {
	f, err := auth.LoadTokenFile(path)
	if err != nil {
		return err
	}
	if len(f.Tokens) == 0 {
		fmt.Fprintf(out, "No tokens in %s\n", path)
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tACCOUNT\tNAME\tLIMITS\tEXPIRES\tSTATUS")
	for _, t := range f.Sorted() {
		acct, _ := f.Account(t.AccountID)
		status, exp := "active", "never"
		if t.ExpiresAt != nil {
			exp = t.ExpiresAt.Local().Format("2006-01-02 15:04")
			if time.Now().After(*t.ExpiresAt) {
				status = "expired"
			}
		}
		if !acct.Active {
			status = "account disabled"
		}
		if t.Revoked {
			status = "revoked"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, acct.Name, t.Name, describeLimits(acct), exp, status)
	}
	return tw.Flush()
}

func describeLimits(a auth.FileAccount) string {
	var parts []string
	if a.MaxTunnels > 0 {
		parts = append(parts, "tunnels<="+strconv.Itoa(a.MaxTunnels))
	}
	if a.MaxSessions > 0 {
		parts = append(parts, "sessions<="+strconv.Itoa(a.MaxSessions))
	}
	if a.RateLimit > 0 {
		parts = append(parts, "rate="+strconv.Itoa(a.RateLimit)+"/s")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func tokenRevoke(path string, out io.Writer, id string) error {
	f, err := auth.LoadTokenFile(path)
	if err != nil {
		return err
	}
	if err := f.Revoke(id); err != nil {
		return err
	}
	if err := f.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(out, "Token %s revoked.\n", id)
	return nil
}

// parseLifetime parses a duration with an optional "d" (days) suffix.
func parseLifetime(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid lifetime %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid lifetime %q", s)
	}
	return d, nil
}
