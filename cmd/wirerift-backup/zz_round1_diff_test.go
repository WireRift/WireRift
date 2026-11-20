package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Differential fidelity: does a restore reproduce the source tree exactly
// (paths, modes, contents)?
func TestRestoreFidelityDiff(t *testing.T) {
	src := t.TempDir()
	restore := t.TempDir()

	mustWrite := func(rel string, mode os.FileMode, body string) {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("tokens.json", 0o600, "{\"accounts\":[]}")
	mustWrite("certs/server.crt", 0o644, "CERT")
	mustWrite("certs/server.key", 0o600, "KEY")
	mustWrite("certs/nested/deep/leaf.txt", 0o400, "leaf")
	mustWrite("empty.txt", 0o644, "")
	if err := os.MkdirAll(filepath.Join(src, "emptydir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "emptydir"), 0o750); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	out := filepath.Join(t.TempDir(), "b.wrb")
	if _, err := createBackup(src, out, key); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := restoreBackup(out, restore, key); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Compare the two trees.
	var diffs []string
	walk := func(root string) map[string]string {
		m := map[string]string{}
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if rel == "." {
				return nil
			}
			m[rel] = info.Mode().Perm().String()
			return nil
		})
		return m
	}
	a, b := walk(src), walk(restore)
	for k, v := range a {
		if bv, ok := b[k]; !ok {
			diffs = append(diffs, "MISSING in restore: "+k)
		} else if bv != v {
			diffs = append(diffs, "MODE differs: "+k+" src="+v+" restored="+bv)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			diffs = append(diffs, "EXTRA in restore: "+k)
		}
	}
	// Content check
	for k := range a {
		sb, e1 := os.ReadFile(filepath.Join(src, k))
		rb, e2 := os.ReadFile(filepath.Join(restore, k))
		if e1 == nil && e2 == nil && string(sb) != string(rb) {
			diffs = append(diffs, "CONTENT differs: "+k)
		}
	}
	for _, d := range diffs {
		t.Errorf("DIFF: %s", d)
	}
}
