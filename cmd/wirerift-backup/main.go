// Command wirerift-backup creates, verifies, and restores encrypted WireRift
// state backups. The encryption key must be stored outside the state volume.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	var err error
	switch args[0] {
	case "create":
		err = runCreate(args[1:], stdout, stderr)
	case "verify":
		err = runVerify(args[1:], stdout, stderr)
	case "restore":
		err = runRestore(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "wirerift-backup %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func runCreate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", "WireRift state directory")
	output := fs.String("output", "", "new encrypted backup path")
	keyPath := fs.String("key", "", "separate AES-256 key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *output == "" || *keyPath == "" {
		return fmt.Errorf("create requires --source, --output, and --key")
	}
	if err := ensurePathOutside(*source, *keyPath, "key"); err != nil {
		return err
	}
	if err := ensurePathOutside(*source, *output, "output"); err != nil {
		return err
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	m, err := createBackup(*source, *output, key)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "created backup_id=%s files=%d output=%s\n", m.BackupID, countFiles(m), *output)
	return nil
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "", "encrypted backup path")
	keyPath := fs.String("key", "", "AES-256 key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *input == "" || *keyPath == "" {
		return fmt.Errorf("verify requires --input and --key")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	m, err := verifyBackup(*input, key)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified backup_id=%s files=%d created_at=%s\n", m.BackupID, countFiles(m), m.CreatedAt)
	return nil
}

func runRestore(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "", "encrypted backup path")
	target := fs.String("target", "", "new empty restore path")
	keyPath := fs.String("key", "", "AES-256 key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *input == "" || *target == "" || *keyPath == "" {
		return fmt.Errorf("restore requires --input, --target, and --key")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	m, err := restoreBackup(*input, *target, key)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "restored backup_id=%s files=%d target=%s\n", m.BackupID, countFiles(m), *target)
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  wirerift-backup create  --source STATE_DIR --output BACKUP.wrb --key KEY_FILE")
	fmt.Fprintln(w, "  wirerift-backup verify  --input BACKUP.wrb --key KEY_FILE")
	fmt.Fprintln(w, "  wirerift-backup restore --input BACKUP.wrb --target NEW_DIR --key KEY_FILE")
}
