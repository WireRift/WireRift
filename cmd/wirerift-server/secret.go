package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wirerift/wirerift/internal/server"
)

const domainSecretFile = "domain-secret"

// errEmptySecret marks a secret file that exists but holds nothing. It wraps
// os.ErrNotExist so callers treat it as "not created yet".
var errEmptySecret = fmt.Errorf("secret file is empty: %w", os.ErrNotExist)

// loadOrCreateDomainSecret returns the secret that keys custom-domain DNS
// proofs, creating it (mode 0600) on first use. Persisting it keeps the TXT
// records users published valid across restarts.
func loadOrCreateDomainSecret(dir string) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, domainSecretFile)

	secret, err := readDomainSecret(path)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if errors.Is(err, errEmptySecret) {
		// What a crash between create and write used to leave behind. Nothing
		// was ever derived from it, so it is safe to replace. Re-check right
		// before deleting so a secret another process just wrote survives.
		if data, rerr := os.ReadFile(path); rerr == nil && strings.TrimSpace(string(data)) == "" {
			_ = os.Remove(path)
		}
	}

	// Write the secret to a private temp file first and publish it with an
	// atomic link: readers and crashes never see a partial file, and when two
	// processes race the loser adopts the winner's secret.
	secret = server.NewDomainSecret()
	tmp, err := os.CreateTemp(dir, ".domain-secret-*") // mode 0600
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(hex.EncodeToString(secret) + "\n"); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}

	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readDomainSecret(path) // another process won the race
		}
		// No hard-link support (some filesystems): rename, unless it appeared meanwhile.
		if _, serr := os.Stat(path); serr == nil {
			return readDomainSecret(path)
		}
		if rerr := os.Rename(tmpName, path); rerr != nil {
			return nil, fmt.Errorf("create %s: %w", path, rerr)
		}
	}
	return secret, nil
}

// readDomainSecret reads and validates an existing secret file without creating
// anything. A missing file wraps os.ErrNotExist.
func readDomainSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		// Nothing was ever written (an interrupted older version): no proof
		// can have been derived from it. Reported as "missing" so it is healed.
		return nil, fmt.Errorf("%s is empty: %w", path, errEmptySecret)
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(secret) < 32 {
		// Never silently replace it: that would invalidate every published TXT record.
		return nil, fmt.Errorf("%s is corrupt; fix or delete it (published DNS proofs will change)", path)
	}
	return secret, nil
}
