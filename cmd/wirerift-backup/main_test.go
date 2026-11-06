package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBackupRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "state")
	mustMkdir(t, filepath.Join(source, "nested"), 0o750)
	mustWrite(t, filepath.Join(source, "tokens.json"), []byte(`{"tokens":["secret-token"]}`), 0o640)
	mustWrite(t, filepath.Join(source, "nested", "domain.key"), []byte("private-key-material"), 0o600)
	mustMkdir(t, filepath.Join(source, "empty"), 0o700)

	key := testKey(1)
	backup := filepath.Join(root, "state.wrb")
	created, err := createBackup(source, backup, key)
	if err != nil {
		t.Fatalf("createBackup: %v", err)
	}
	if got := countFiles(created); got != 2 {
		t.Fatalf("file count = %d, want 2", got)
	}
	raw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-token")) || bytes.Contains(raw, []byte("private-key-material")) {
		t.Fatal("encrypted backup exposes plaintext state")
	}

	verified, err := verifyBackup(backup, key)
	if err != nil {
		t.Fatalf("verifyBackup: %v", err)
	}
	if verified.BackupID != created.BackupID {
		t.Fatalf("verified backup ID = %q, want %q", verified.BackupID, created.BackupID)
	}

	target := filepath.Join(root, "restored")
	restored, err := restoreBackup(backup, target, key)
	if err != nil {
		t.Fatalf("restoreBackup: %v", err)
	}
	if restored.BackupID != created.BackupID {
		t.Fatalf("restored backup ID = %q, want %q", restored.BackupID, created.BackupID)
	}
	assertFile(t, filepath.Join(target, "tokens.json"), []byte(`{"tokens":["secret-token"]}`), 0o640)
	assertFile(t, filepath.Join(target, "nested", "domain.key"), []byte("private-key-material"), 0o600)
	if info, err := os.Stat(filepath.Join(target, "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty directory was not restored: info=%v err=%v", info, err)
	}
}

func TestBackupRejectsWrongKeyCorruptionAndTruncation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "state")
	mustMkdir(t, source, 0o700)
	mustWrite(t, filepath.Join(source, "held.json"), []byte(`{"held":[]}`), 0o600)
	backup := filepath.Join(root, "state.wrb")
	key := testKey(2)
	if _, err := createBackup(source, backup, key); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBackup(backup, testKey(3)); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong key error = %v, want authentication failure", err)
	}

	raw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)/2] ^= 0x80
	corruptName := filepath.Join(root, "corrupt.wrb")
	mustWrite(t, corruptName, corrupt, 0o600)
	if _, err := verifyBackup(corruptName, key); err == nil {
		t.Fatal("corrupted backup unexpectedly verified")
	}

	truncatedName := filepath.Join(root, "truncated.wrb")
	mustWrite(t, truncatedName, raw[:len(raw)-1], 0o600)
	if _, err := verifyBackup(truncatedName, key); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated backup error = %v", err)
	}
}

func TestRestoreNeverClobbersExistingTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "state")
	mustMkdir(t, source, 0o700)
	mustWrite(t, filepath.Join(source, "tokens.json"), []byte("new"), 0o600)
	backup := filepath.Join(root, "state.wrb")
	key := testKey(4)
	if _, err := createBackup(source, backup, key); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	mustMkdir(t, target, 0o700)
	marker := filepath.Join(target, "do-not-touch")
	mustWrite(t, marker, []byte("original"), 0o600)
	if _, err := restoreBackup(backup, target, key); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("restore error = %v, want existing-target rejection", err)
	}
	assertFile(t, marker, []byte("original"), 0o600)

	if _, err := createBackup(source, backup, key); err == nil || !strings.Contains(err.Error(), "output already exists") {
		t.Fatalf("second create error = %v, want existing-output rejection", err)
	}
}

func TestRestoreAcceptsFreshMountedDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "state")
	mustMkdir(t, source, 0o700)
	mustWrite(t, filepath.Join(source, "tokens.json"), []byte("token"), 0o600)
	backup := filepath.Join(root, "state.wrb")
	key := testKey(13)
	if _, err := createBackup(source, backup, key); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "mounted-volume")
	mustMkdir(t, target, 0o700)
	if _, err := restoreBackup(backup, target, key); err != nil {
		t.Fatalf("restore into empty directory: %v", err)
	}
	assertFile(t, filepath.Join(target, "tokens.json"), []byte("token"), 0o600)
	matches, err := filepath.Glob(filepath.Join(target, ".wirerift-restore-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("restore staging residue = %v, err=%v", matches, err)
	}
}

func TestVerifyRejectsUnsafeAndUnsupportedEntries(t *testing.T) {
	t.Parallel()
	key := testKey(5)
	tests := []struct {
		name     string
		header   tar.Header
		wantText string
	}{
		{
			name:     "parent traversal",
			header:   tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o600},
			wantText: "unsafe archive path",
		},
		{
			name:     "absolute path",
			header:   tar.Header{Name: "/escape", Typeflag: tar.TypeReg, Mode: 0o600},
			wantText: "unsafe archive path",
		},
		{
			name:     "symlink",
			header:   tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../outside", Mode: 0o777},
			wantText: "unsupported entry",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			archive := makeEncryptedTar(t, key, func(tw *tar.Writer) {
				if err := tw.WriteHeader(&tc.header); err != nil {
					t.Fatal(err)
				}
			})
			_, err := inspectArchive(bytes.NewReader(archive), key, "")
			if err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error = %v, want %q", err, tc.wantText)
			}
		})
	}
}

func TestVerifyRejectsManifestMismatch(t *testing.T) {
	t.Parallel()
	key := testKey(6)
	m := manifest{
		FormatVersion: backupFormatVersion,
		BackupID:      strings.Repeat("a", 32),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Entries: []manifestEntry{{
			Path: "tokens.json", Type: "file", Size: 5, Mode: 0o600,
			SHA256: strings.Repeat("0", 64),
		}},
	}
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	archive := makeEncryptedTar(t, key, func(tw *tar.Writer) {
		writeTarFile(t, tw, "tokens.json", []byte("token"), 0o600)
		writeTarFile(t, tw, manifestName, manifestJSON, 0o600)
	})
	if _, err := inspectArchive(bytes.NewReader(archive), key, ""); err == nil || !strings.Contains(err.Error(), "manifest mismatch") {
		t.Fatalf("error = %v, want manifest mismatch", err)
	}
}

func TestCreateRejectsUnsafeSourceAndPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "state")
	mustMkdir(t, source, 0o700)
	mustWrite(t, filepath.Join(source, "tokens.json"), []byte("token"), 0o600)
	key := testKey(7)

	if _, err := createBackup(source, filepath.Join(source, "backup.wrb"), key); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("inside output error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("tokens.json", filepath.Join(source, "token-link")); err != nil {
			t.Fatal(err)
		}
		if _, err := createBackup(source, filepath.Join(root, "backup.wrb"), key); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink source error = %v", err)
		}
	}
}

func TestCLIKeyContractAndRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "state")
	mustMkdir(t, source, 0o700)
	mustWrite(t, filepath.Join(source, "domain-secret"), []byte("secret"), 0o600)
	keyPath := filepath.Join(root, "backup.key")
	mustWrite(t, keyPath, []byte(hex.EncodeToString(testKey(8))+"\n"), 0o600)
	backup := filepath.Join(root, "state.wrb")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"create", "--source", source, "--output", backup, "--key", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("create code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "--input", backup, "--key", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	target := filepath.Join(root, "restored")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"restore", "--input", backup, "--target", target, "--key", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("restore code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	assertFile(t, filepath.Join(target, "domain-secret"), []byte("secret"), 0o600)

	insideKey := filepath.Join(source, "backup.key")
	mustWrite(t, insideKey, []byte(hex.EncodeToString(testKey(9))+"\n"), 0o600)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"create", "--source", source, "--output", filepath.Join(root, "second.wrb"), "--key", insideKey}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "key must be outside") {
		t.Fatalf("inside-key code=%d stderr=%q", code, stderr.String())
	}
}

func TestCLIUsageAndArgumentErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantText string
	}{
		{name: "no command", wantCode: 2, wantText: "usage:"},
		{name: "unknown command", args: []string{"unknown"}, wantCode: 2, wantText: "unknown command"},
		{name: "help", args: []string{"help"}, wantCode: 0, wantText: "wirerift-backup create"},
		{name: "create missing", args: []string{"create"}, wantCode: 1, wantText: "requires --source"},
		{name: "verify missing", args: []string{"verify"}, wantCode: 1, wantText: "requires --input"},
		{name: "restore missing", args: []string{"restore"}, wantCode: 1, wantText: "requires --input"},
		{name: "bad flag", args: []string{"create", "--not-a-flag"}, wantCode: 1, wantText: "flag provided but not defined"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			if code != tc.wantCode || !strings.Contains(combined, tc.wantText) {
				t.Fatalf("code=%d output=%q, want code=%d containing %q", code, combined, tc.wantCode, tc.wantText)
			}
		})
	}
}

func TestKeyLoadingAndPathContracts(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	rawName := filepath.Join(root, "raw.key")
	mustWrite(t, rawName, testKey(21), 0o600)
	got, err := loadKey(rawName)
	if err != nil || !bytes.Equal(got, testKey(21)) {
		t.Fatalf("raw key = %x, err=%v", got, err)
	}
	badName := filepath.Join(root, "bad.key")
	mustWrite(t, badName, []byte("not-a-key"), 0o600)
	if _, err := loadKey(badName); err == nil || !strings.Contains(err.Error(), "32 raw bytes") {
		t.Fatalf("invalid key error = %v", err)
	}
	if _, err := loadKey(root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory key error = %v", err)
	}
	if _, err := loadKey(filepath.Join(root, "missing")); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("missing key error = %v", err)
	}
	if err := ensurePathOutside(root, root, "candidate"); err == nil {
		t.Fatal("root path unexpectedly accepted as outside")
	}
	if err := ensurePathOutside(root, filepath.Join(root, "child"), "candidate"); err == nil {
		t.Fatal("child path unexpectedly accepted as outside")
	}
	if err := ensurePathOutside(root, filepath.Join(filepath.Dir(root), "sibling"), "candidate"); err != nil {
		t.Fatalf("sibling path rejected: %v", err)
	}
}

func TestManifestValidationFailures(t *testing.T) {
	t.Parallel()
	validEntry := manifestEntry{
		Path: "tokens.json", Type: "file", Size: 5, Mode: 0o600,
		SHA256: strings.Repeat("a", 64),
	}
	valid := manifest{
		FormatVersion: backupFormatVersion,
		BackupID:      strings.Repeat("b", 32),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Entries:       []manifestEntry{validEntry},
	}
	observed := map[string]manifestEntry{"tokens.json": validEntry}
	if err := validateManifest(valid, observed); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*manifest)
		want   string
	}{
		{name: "format", mutate: func(m *manifest) { m.FormatVersion++ }, want: "unsupported manifest format"},
		{name: "short ID", mutate: func(m *manifest) { m.BackupID = "bad" }, want: "backup ID"},
		{name: "nonhex ID", mutate: func(m *manifest) { m.BackupID = strings.Repeat("z", 32) }, want: "backup ID"},
		{name: "time", mutate: func(m *manifest) { m.CreatedAt = "yesterday" }, want: "creation time"},
		{name: "unsafe path", mutate: func(m *manifest) { m.Entries[0].Path = "../tokens.json" }, want: "unsafe path"},
		{name: "reserved path", mutate: func(m *manifest) { m.Entries[0].Path = manifestName }, want: "unsafe path"},
		{name: "duplicate", mutate: func(m *manifest) { m.Entries = append(m.Entries, m.Entries[0]) }, want: "inventory"},
		{name: "unsupported type", mutate: func(m *manifest) { m.Entries[0].Type = "link" }, want: "unsupported type"},
		{name: "mode", mutate: func(m *manifest) { m.Entries[0].Mode = 0o1000 }, want: "invalid mode"},
		{name: "digest length", mutate: func(m *manifest) { m.Entries[0].SHA256 = "abc" }, want: "invalid digest"},
		{name: "digest hex", mutate: func(m *manifest) { m.Entries[0].SHA256 = strings.Repeat("z", 64) }, want: "invalid digest"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			candidate.Entries = append([]manifestEntry(nil), valid.Entries...)
			tc.mutate(&candidate)
			candidateObserved := observed
			if tc.name == "unsupported type" || tc.name == "mode" || strings.HasPrefix(tc.name, "digest") {
				candidateObserved = map[string]manifestEntry{candidate.Entries[0].Path: candidate.Entries[0]}
			}
			if err := validateManifest(candidate, candidateObserved); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}

	dirEntry := manifestEntry{Path: "empty", Type: "dir", Mode: 0o700, Size: 1}
	dirManifest := valid
	dirManifest.Entries = []manifestEntry{dirEntry}
	if err := validateManifest(dirManifest, map[string]manifestEntry{"empty": dirEntry}); err == nil || !strings.Contains(err.Error(), "directory metadata") {
		t.Fatalf("directory metadata error = %v", err)
	}
}

func TestEncryptedFrameValidationFailures(t *testing.T) {
	t.Parallel()
	key := testKey(22)
	if _, err := newEncryptWriter(io.Discard, []byte("short")); err == nil || !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("short encrypt key error = %v", err)
	}
	if _, err := newDecryptReader(bufio.NewReader(bytes.NewReader([]byte("short"))), key); err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("short header error = %v", err)
	}
	badMagic := append([]byte("BADMAG!"), make([]byte, 8)...)
	if _, err := newDecryptReader(bufio.NewReader(bytes.NewReader(badMagic)), key); err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("bad magic error = %v", err)
	}

	prefix := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	base := append(append([]byte{}, backupMagic...), prefix[:]...)
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "missing frame", body: nil, want: "truncated"},
		{name: "invalid type", body: []byte{9, 0, 0, 0, 16}, want: "frame type"},
		{name: "short length", body: []byte{frameData, 0, 0, 0, 1, 0}, want: "frame length"},
		{name: "truncated ciphertext", body: []byte{frameData, 0, 0, 0, 16, 0}, want: "truncated"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dr, err := newDecryptReader(bufio.NewReader(bytes.NewReader(append(append([]byte{}, base...), tc.body...))), key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, dr); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}

	invalidFinal := encryptedFrame(t, key, prefix, 0, frameFinal, []byte("not-empty"))
	dr, err := newDecryptReader(bufio.NewReader(bytes.NewReader(append(append([]byte{}, base...), invalidFinal...))), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, dr); err == nil || !strings.Contains(err.Error(), "invalid final frame") {
		t.Fatalf("invalid final error = %v", err)
	}

	emptyData := encryptedFrame(t, key, prefix, 0, frameData, nil)
	dr, err = newDecryptReader(bufio.NewReader(bytes.NewReader(append(append([]byte{}, base...), emptyData...))), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, dr); err == nil || !strings.Contains(err.Error(), "empty data frame") {
		t.Fatalf("empty data error = %v", err)
	}

	var encrypted bytes.Buffer
	ew, err := newEncryptWriter(&encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ew.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := ew.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := ew.Write([]byte("late")); err == nil || !strings.Contains(err.Error(), "after close") {
		t.Fatalf("write-after-close error = %v", err)
	}
}

func TestArchiveRestoreLimits(t *testing.T) {
	t.Parallel()
	regular := &tar.Header{Name: "state.bin", Typeflag: tar.TypeReg, Size: 1}
	if total, err := checkArchiveEntryLimits(regular, 1, 0); err != nil || total != 1 {
		t.Fatalf("valid entry total=%d err=%v", total, err)
	}
	tests := []struct {
		name  string
		hdr   tar.Header
		count int
		total int64
		want  string
	}{
		{name: "entry count", hdr: *regular, count: maxArchiveEntries + 1, want: "too many entries"},
		{name: "single file", hdr: tar.Header{Name: "huge", Typeflag: tar.TypeReg, Size: maxFileSize + 1}, count: 1, want: "size limit"},
		{name: "aggregate", hdr: *regular, count: 2, total: maxArchiveDataSize, want: "size limit"},
		{name: "negative", hdr: tar.Header{Name: "negative", Typeflag: tar.TypeReg, Size: -1}, count: 1, want: "size limit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := checkArchiveEntryLimits(&tc.hdr, tc.count, tc.total); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	directory := &tar.Header{Name: "empty", Typeflag: tar.TypeDir}
	if total, err := checkArchiveEntryLimits(directory, 1, 42); err != nil || total != 42 {
		t.Fatalf("directory total=%d err=%v", total, err)
	}
}

func encryptedFrame(t *testing.T, key []byte, prefix [8]byte, index uint32, flag byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, frameNonce(prefix, index), plaintext, frameAAD(prefix, index, flag))
	header := make([]byte, 5)
	header[0] = flag
	binary.BigEndian.PutUint32(header[1:], uint32(len(ciphertext)))
	return append(header, ciphertext...)
}

func makeEncryptedTar(t *testing.T, key []byte, populate func(*tar.Writer)) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encrypted, err := newEncryptWriter(&buffer, key)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(encrypted)
	tw := tar.NewWriter(gz)
	populate(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeTarFile(t *testing.T, tw *tar.Writer, name string, body []byte, mode int64) {
	t.Helper()
	hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
}

func testKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 32)
}

func mustMkdir(t *testing.T, name string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(name, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, name string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(name, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, name string, want []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if gotMode := info.Mode().Perm(); gotMode != mode {
			t.Fatalf("%s mode = %04o, want %04o", name, gotMode, mode)
		}
	}
}

func TestDecryptRejectsTrailingData(t *testing.T) {
	t.Parallel()
	key := testKey(10)
	archive := makeEncryptedTar(t, key, func(tw *tar.Writer) {})
	archive = append(archive, []byte("trailing")...)
	_, err := inspectArchive(bytes.NewReader(archive), key, "")
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("error = %v, want trailing-data rejection", err)
	}
}

func TestLoadKeyRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission bits do not represent ACL access")
	}
	t.Parallel()
	name := filepath.Join(t.TempDir(), "key")
	mustWrite(t, name, testKey(11), 0o644)
	if _, err := loadKey(name); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("error = %v, want permission rejection", err)
	}
}

func TestDecryptReaderReturnsEOFOnlyAfterFinalFrame(t *testing.T) {
	t.Parallel()
	key := testKey(12)
	archive := makeEncryptedTar(t, key, func(tw *tar.Writer) {})
	reader, err := newDecryptReader(bufio.NewReader(bytes.NewReader(archive)), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("final read error = %v, want EOF", err)
	}
}
