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

// loadOrCreateDomainSecret returns the secret that keys custom-domain DNS
// proofs, creating it (mode 0600) on first use. Persisting it keeps the TXT
// records users published valid across restarts.
func loadOrCreateDomainSecret(dir string) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, domainSecretFile)

	if secret, err := readDomainSecret(path); err == nil {
		return secret, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	secret := server.NewDomainSecret()
	// O_EXCL: if another process created it meanwhile, use theirs.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateDomainSecret(dir)
	}
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(secret) + "\n"); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
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
	secret, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(secret) < 32 {
		// Never silently replace it: that would invalidate every published TXT record.
		return nil, fmt.Errorf("%s is corrupt; fix or delete it (published DNS proofs will change)", path)
	}
	return secret, nil
}
