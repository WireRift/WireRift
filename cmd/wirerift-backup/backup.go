package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	backupFormatVersion      = 1
	chunkSize                = 1 << 20
	manifestName             = ".wirerift-backup-manifest.json"
	maxManifestSize          = 16 << 20
	maxFileSize              = 1 << 30
	maxArchiveDataSize       = 4 << 30
	maxArchiveEntries        = 100000
	frameData           byte = 0
	frameFinal          byte = 1
	entryTypeFile            = "file"
	entryTypeDirectory       = "dir"
)

var backupMagic = []byte("WRBKP1\n")

type manifest struct {
	FormatVersion int             `json:"format_version"`
	BackupID      string          `json:"backup_id"`
	CreatedAt     string          `json:"created_at"`
	Entries       []manifestEntry `json:"entries"`
}

type manifestEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
}

type sourceEntry struct {
	absPath string
	relPath string
	info    os.FileInfo
}

func countFiles(m manifest) int {
	n := 0
	for _, entry := range m.Entries {
		if entry.Type == entryTypeFile {
			n++
		}
	}
	return n
}

func loadKey(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("read key metadata: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key permissions %04o are too broad; require 0600 or stricter", info.Mode().Perm())
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	if len(raw) == 32 {
		return raw, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 64 {
		decoded, decodeErr := hex.DecodeString(trimmed)
		if decodeErr == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("key must contain exactly 32 raw bytes or 64 hexadecimal characters (create one with: openssl rand -hex 32)")
}

func ensurePathOutside(root, candidate, label string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", label, err)
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return fmt.Errorf("compare source and %s: %w", label, err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("%s must be outside the state directory", label)
	}
	return nil
}

func createBackup(source, output string, key []byte) (manifest, error) {
	if err := ensurePathOutside(source, output, "output"); err != nil {
		return manifest{}, err
	}
	entries, err := collectSource(source)
	if err != nil {
		return manifest{}, err
	}
	if _, err := os.Lstat(output); err == nil {
		return manifest{}, fmt.Errorf("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest{}, fmt.Errorf("inspect output: %w", err)
	}

	backupIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, backupIDBytes); err != nil {
		return manifest{}, fmt.Errorf("generate backup ID: %w", err)
	}
	m := manifest{
		FormatVersion: backupFormatVersion,
		BackupID:      hex.EncodeToString(backupIDBytes),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}

	parent := filepath.Dir(output)
	tmp, err := os.CreateTemp(parent, ".wirerift-backup-*")
	if err != nil {
		return manifest{}, fmt.Errorf("create temporary backup: %w", err)
	}
	tmpName := tmp.Name()
	keepTemp := false
	defer func() {
		_ = tmp.Close()
		if !keepTemp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return manifest{}, fmt.Errorf("secure temporary backup: %w", err)
	}

	encrypted, err := newEncryptWriter(tmp, key)
	if err != nil {
		return manifest{}, err
	}
	gz := gzip.NewWriter(encrypted)
	tw := tar.NewWriter(gz)
	writeErr := writeArchive(tw, entries, &m)
	if closeErr := tw.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if closeErr := gz.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if closeErr := encrypted.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return manifest{}, fmt.Errorf("write backup: %w", writeErr)
	}
	if err := tmp.Sync(); err != nil {
		return manifest{}, fmt.Errorf("sync backup: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return manifest{}, fmt.Errorf("close backup: %w", err)
	}
	if err := os.Link(tmpName, output); err != nil {
		if errors.Is(err, os.ErrExist) {
			return manifest{}, fmt.Errorf("output already exists")
		}
		return manifest{}, fmt.Errorf("publish backup without overwrite: %w", err)
	}
	if err := os.Remove(tmpName); err != nil {
		_ = os.Remove(output)
		return manifest{}, fmt.Errorf("finalize backup: %w", err)
	}
	keepTemp = true
	if err := syncDirectory(parent); err != nil {
		return manifest{}, err
	}
	return m, nil
}

func collectSource(source string) ([]sourceEntry, error) {
	rootInfo, err := os.Lstat(source)
	if err != nil {
		return nil, fmt.Errorf("inspect source: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("source must be a directory")
	}
	rootAbs, err := filepath.Abs(source)
	if err != nil {
		return nil, fmt.Errorf("resolve source: %w", err)
	}
	var entries []sourceEntry
	err = filepath.Walk(rootAbs, func(name string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == rootAbs {
			return nil
		}
		rel, err := filepath.Rel(rootAbs, name)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == manifestName {
			return fmt.Errorf("source contains reserved path %q", manifestName)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains symlink %q", rel)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("source contains unsupported file %q", rel)
		}
		entries = append(entries, sourceEntry{absPath: name, relPath: rel, info: info})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk source: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relPath < entries[j].relPath })
	return entries, nil
}

func writeArchive(tw *tar.Writer, entries []sourceEntry, m *manifest) error {
	for _, entry := range entries {
		hdr, err := tar.FileInfoHeader(entry.info, "")
		if err != nil {
			return fmt.Errorf("header %q: %w", entry.relPath, err)
		}
		hdr.Name = entry.relPath
		hdr.Uid = 0
		hdr.Gid = 0
		hdr.Uname = ""
		hdr.Gname = ""
		if entry.info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write header %q: %w", entry.relPath, err)
		}
		item := manifestEntry{
			Path: entry.relPath,
			Mode: uint32(entry.info.Mode().Perm()),
		}
		if entry.info.IsDir() {
			item.Type = entryTypeDirectory
			m.Entries = append(m.Entries, item)
			continue
		}
		item.Type = entryTypeFile
		item.Size = entry.info.Size()
		file, err := os.Open(entry.absPath)
		if err != nil {
			return fmt.Errorf("open %q: %w", entry.relPath, err)
		}
		openedInfo, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("inspect opened file %q: %w", entry.relPath, err)
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(entry.info, openedInfo) {
			_ = file.Close()
			return fmt.Errorf("file %q changed before backup", entry.relPath)
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(tw, hash), file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("read %q: %w", entry.relPath, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %q: %w", entry.relPath, closeErr)
		}
		if written != entry.info.Size() {
			return fmt.Errorf("file %q changed size during backup", entry.relPath)
		}
		after, err := os.Lstat(entry.absPath)
		if err != nil || after.Size() != entry.info.Size() || !after.ModTime().Equal(entry.info.ModTime()) || after.Mode() != entry.info.Mode() {
			return fmt.Errorf("file %q changed during backup", entry.relPath)
		}
		item.SHA256 = hex.EncodeToString(hash.Sum(nil))
		m.Entries = append(m.Entries, item)
	}

	manifestJSON, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	hdr := &tar.Header{
		Name:     manifestName,
		Mode:     0o600,
		Size:     int64(len(manifestJSON)),
		ModTime:  time.Now().UTC(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write manifest header: %w", err)
	}
	if _, err := tw.Write(manifestJSON); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func verifyBackup(input string, key []byte) (manifest, error) {
	file, err := os.Open(input)
	if err != nil {
		return manifest{}, fmt.Errorf("open backup: %w", err)
	}
	defer file.Close()
	return inspectArchive(file, key, "")
}

func restoreBackup(input, target string, key []byte) (manifest, error) {
	targetExists := false
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() {
			return manifest{}, fmt.Errorf("target already exists and is not an empty directory")
		}
		empty, err := directoryEmpty(target)
		if err != nil {
			return manifest{}, err
		}
		if !empty {
			return manifest{}, fmt.Errorf("target already exists and is not empty")
		}
		targetExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest{}, fmt.Errorf("inspect target: %w", err)
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return manifest{}, fmt.Errorf("create target parent: %w", err)
	}
	stageParent := parent
	if targetExists {
		// A mounted fresh volume necessarily exists. Stage inside it so all
		// plaintext is authenticated before any final path becomes visible.
		stageParent = target
	}
	stage, err := os.MkdirTemp(stageParent, ".wirerift-restore-*")
	if err != nil {
		return manifest{}, fmt.Errorf("create restore staging directory: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = os.RemoveAll(stage)
		}
	}()

	file, err := os.Open(input)
	if err != nil {
		return manifest{}, fmt.Errorf("open backup: %w", err)
	}
	m, inspectErr := inspectArchive(file, key, stage)
	closeErr := file.Close()
	if inspectErr != nil {
		return manifest{}, inspectErr
	}
	if closeErr != nil {
		return manifest{}, fmt.Errorf("close backup: %w", closeErr)
	}
	if err := syncDirectory(stage); err != nil {
		return manifest{}, err
	}
	if targetExists {
		if err := publishStagedContents(stage, target); err != nil {
			return manifest{}, err
		}
		if err := syncDirectory(target); err != nil {
			return manifest{}, err
		}
	} else {
		if _, err := os.Lstat(target); err == nil {
			return manifest{}, fmt.Errorf("target appeared during restore")
		} else if !errors.Is(err, os.ErrNotExist) {
			return manifest{}, fmt.Errorf("inspect target: %w", err)
		}
		if err := os.Rename(stage, target); err != nil {
			return manifest{}, fmt.Errorf("publish restored state: %w", err)
		}
	}
	keepStage = true
	if err := syncDirectory(parent); err != nil {
		return manifest{}, err
	}
	return m, nil
}

func directoryEmpty(name string) (bool, error) {
	dir, err := os.Open(name)
	if err != nil {
		return false, fmt.Errorf("open target: %w", err)
	}
	defer dir.Close()
	_, err = dir.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect target contents: %w", err)
	}
	return false, nil
}

func publishStagedContents(stage, target string) error {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return fmt.Errorf("read verified restore: %w", err)
	}
	moved := make([]string, 0, len(entries))
	rollback := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.Rename(filepath.Join(target, moved[i]), filepath.Join(stage, moved[i]))
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		finalName := filepath.Join(target, name)
		if _, err := os.Lstat(finalName); err == nil {
			rollback()
			return fmt.Errorf("restore target changed while publishing")
		} else if !errors.Is(err, os.ErrNotExist) {
			rollback()
			return fmt.Errorf("inspect restore destination: %w", err)
		}
		if err := os.Rename(filepath.Join(stage, name), finalName); err != nil {
			rollback()
			return fmt.Errorf("publish restored path %q: %w", name, err)
		}
		moved = append(moved, name)
	}
	if err := os.Remove(stage); err != nil {
		rollback()
		return fmt.Errorf("remove restore staging directory: %w", err)
	}
	return nil
}

func inspectArchive(input io.Reader, key []byte, destination string) (manifest, error) {
	decrypted, err := newDecryptReader(bufio.NewReader(input), key)
	if err != nil {
		return manifest{}, err
	}
	gz, err := gzip.NewReader(decrypted)
	if err != nil {
		return manifest{}, fmt.Errorf("open compressed backup: %w", err)
	}
	tr := tar.NewReader(gz)
	observed := make(map[string]manifestEntry)
	var m manifest
	manifestSeen := false
	entryCount := 0
	var archiveDataSize int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return manifest{}, fmt.Errorf("read archive: %w", err)
		}
		if manifestSeen {
			return manifest{}, fmt.Errorf("archive contains data after manifest")
		}
		name, err := safeArchivePath(hdr.Name)
		if err != nil {
			return manifest{}, err
		}
		if name == manifestName {
			if hdr.Typeflag != tar.TypeReg {
				return manifest{}, fmt.Errorf("manifest is not a regular file")
			}
			m, err = decodeManifest(tr, hdr.Size)
			if err != nil {
				return manifest{}, err
			}
			manifestSeen = true
			continue
		}
		entryCount++
		if _, exists := observed[name]; exists {
			return manifest{}, fmt.Errorf("duplicate archive path %q", name)
		}
		archiveDataSize, err = checkArchiveEntryLimits(hdr, entryCount, archiveDataSize)
		if err != nil {
			return manifest{}, err
		}
		item, err := inspectArchiveEntry(tr, hdr, name, destination)
		if err != nil {
			return manifest{}, err
		}
		observed[name] = item
	}
	// tar.Reader stops at its end markers. Require immediate EOF so a second
	// gzip member or decompressed data hidden after the tar terminator is rejected.
	if err := requireEOF(gz); err != nil {
		return manifest{}, fmt.Errorf("authenticate compressed backup trailer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return manifest{}, fmt.Errorf("close compressed backup: %w", err)
	}
	// Force validation of the authenticated final encryption frame even when
	// gzip completed without requesting another byte from its input.
	if err := requireEOF(decrypted); err != nil {
		return manifest{}, fmt.Errorf("authenticate encrypted backup trailer: %w", err)
	}
	if !manifestSeen {
		return manifest{}, fmt.Errorf("archive manifest is missing")
	}
	if err := validateManifest(m, observed); err != nil {
		return manifest{}, err
	}
	if destination != "" {
		if err := applyRestoredModes(destination, m); err != nil {
			return manifest{}, err
		}
	}
	return m, nil
}

func checkArchiveEntryLimits(hdr *tar.Header, entryCount int, archiveDataSize int64) (int64, error) {
	if entryCount > maxArchiveEntries {
		return archiveDataSize, fmt.Errorf("archive contains too many entries")
	}
	if hdr.Typeflag != tar.TypeReg {
		return archiveDataSize, nil
	}
	if hdr.Size < 0 || hdr.Size > maxFileSize || hdr.Size > maxArchiveDataSize-archiveDataSize {
		return archiveDataSize, fmt.Errorf("file %q exceeds restore size limit", hdr.Name)
	}
	return archiveDataSize + hdr.Size, nil
}

func inspectArchiveEntry(tr *tar.Reader, hdr *tar.Header, name, destination string) (manifestEntry, error) {
	mode := uint32(hdr.FileInfo().Mode().Perm())
	if hdr.Typeflag == tar.TypeDir {
		if hdr.Size != 0 {
			return manifestEntry{}, fmt.Errorf("directory %q has invalid size", name)
		}
		if destination != "" {
			full := filepath.Join(destination, filepath.FromSlash(name))
			if err := os.MkdirAll(full, 0o700); err != nil {
				return manifestEntry{}, fmt.Errorf("create directory %q: %w", name, err)
			}
		}
		return manifestEntry{Path: name, Type: entryTypeDirectory, Mode: mode}, nil
	}
	if hdr.Typeflag != tar.TypeReg {
		return manifestEntry{}, fmt.Errorf("archive contains unsupported entry %q", name)
	}

	hash := sha256.New()
	var writer io.Writer = hash
	var out *os.File
	if destination != "" {
		full := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return manifestEntry{}, fmt.Errorf("create parent for %q: %w", name, err)
		}
		var err error
		out, err = os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return manifestEntry{}, fmt.Errorf("create file %q: %w", name, err)
		}
		writer = io.MultiWriter(hash, out)
	}
	written, copyErr := copyBounded(writer, tr, hdr.Size)
	if out != nil {
		if syncErr := out.Sync(); copyErr == nil {
			copyErr = syncErr
		}
		if closeErr := out.Close(); copyErr == nil {
			copyErr = closeErr
		}
	}
	if copyErr != nil {
		return manifestEntry{}, fmt.Errorf("extract %q: %w", name, copyErr)
	}
	return manifestEntry{
		Path: name, Type: entryTypeFile, Size: written, Mode: mode,
		SHA256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func decodeManifest(r io.Reader, size int64) (manifest, error) {
	if size < 0 || size > maxManifestSize {
		return manifest{}, fmt.Errorf("manifest is too large")
	}
	var m manifest
	decoder := json.NewDecoder(io.LimitReader(r, maxManifestSize))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return manifest{}, fmt.Errorf("manifest contains trailing data")
	}
	return m, nil
}

func copyBounded(dst io.Writer, src io.Reader, size int64) (int64, error) {
	buffer := make([]byte, 32*1024)
	var written int64
	for written < size {
		want := int64(len(buffer))
		if remaining := size - written; remaining < want {
			want = remaining
		}
		n, readErr := src.Read(buffer[:want])
		if n > 0 {
			wn, writeErr := dst.Write(buffer[:n])
			written += int64(wn)
			if writeErr != nil {
				return written, writeErr
			}
			if wn != n {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if written == size {
					return written, nil
				}
				return written, io.ErrUnexpectedEOF
			}
			return written, readErr
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func requireEOF(r io.Reader) error {
	var one [1]byte
	for attempts := 0; attempts < 3; attempts++ {
		n, err := r.Read(one[:])
		if n != 0 {
			return fmt.Errorf("trailing data")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return io.ErrNoProgress
}

func applyRestoredModes(destination string, m manifest) error {
	for _, entry := range m.Entries {
		if entry.Type != entryTypeFile {
			continue
		}
		full := filepath.Join(destination, filepath.FromSlash(entry.Path))
		if err := os.Chmod(full, os.FileMode(entry.Mode)); err != nil {
			return fmt.Errorf("set mode on %q: %w", entry.Path, err)
		}
	}
	var directoryEntries []manifestEntry
	for _, entry := range m.Entries {
		if entry.Type == entryTypeDirectory {
			directoryEntries = append(directoryEntries, entry)
		}
	}
	sort.Slice(directoryEntries, func(i, j int) bool {
		return len(directoryEntries[i].Path) > len(directoryEntries[j].Path)
	})
	for _, entry := range directoryEntries {
		full := filepath.Join(destination, filepath.FromSlash(entry.Path))
		if err := syncDirectory(full); err != nil {
			return fmt.Errorf("sync directory %q: %w", entry.Path, err)
		}
		if err := os.Chmod(full, os.FileMode(entry.Mode)); err != nil {
			return fmt.Errorf("set directory mode on %q: %w", entry.Path, err)
		}
	}
	return nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return strings.TrimSuffix(clean, "/"), nil
}

func validateManifest(m manifest, observed map[string]manifestEntry) error {
	if m.FormatVersion != backupFormatVersion {
		return fmt.Errorf("unsupported manifest format %d", m.FormatVersion)
	}
	if len(m.BackupID) != 32 {
		return fmt.Errorf("manifest backup ID is invalid")
	}
	if _, err := hex.DecodeString(m.BackupID); err != nil {
		return fmt.Errorf("manifest backup ID is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return fmt.Errorf("manifest creation time is invalid")
	}
	if len(m.Entries) != len(observed) {
		return fmt.Errorf("manifest inventory does not match archive")
	}
	seen := make(map[string]struct{}, len(m.Entries))
	for _, expected := range m.Entries {
		name, err := safeArchivePath(expected.Path)
		if err != nil || name != expected.Path || name == manifestName {
			return fmt.Errorf("manifest contains unsafe path %q", expected.Path)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("manifest contains duplicate path %q", name)
		}
		seen[name] = struct{}{}
		actual, ok := observed[name]
		if !ok || actual != expected {
			return fmt.Errorf("manifest mismatch for %q", name)
		}
		if expected.Type != entryTypeFile && expected.Type != entryTypeDirectory {
			return fmt.Errorf("manifest contains unsupported type for %q", name)
		}
		if expected.Mode > 0o777 {
			return fmt.Errorf("manifest contains invalid mode for %q", name)
		}
		if expected.Type == entryTypeFile {
			if len(expected.SHA256) != 64 {
				return fmt.Errorf("manifest contains invalid digest for %q", name)
			}
			if _, err := hex.DecodeString(expected.SHA256); err != nil {
				return fmt.Errorf("manifest contains invalid digest for %q", name)
			}
		} else if expected.Size != 0 || expected.SHA256 != "" {
			return fmt.Errorf("manifest contains invalid directory metadata for %q", name)
		}
	}
	return nil
}

func syncDirectory(name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

type encryptWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix [8]byte
	index  uint32
	buf    []byte
	closed bool
}

func newEncryptWriter(w io.Writer, key []byte) (*encryptWriter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize authentication: %w", err)
	}
	ew := &encryptWriter{w: w, aead: aead, buf: make([]byte, 0, chunkSize)}
	if _, err := io.ReadFull(rand.Reader, ew.prefix[:]); err != nil {
		return nil, fmt.Errorf("generate backup nonce: %w", err)
	}
	if _, err := w.Write(append(append([]byte{}, backupMagic...), ew.prefix[:]...)); err != nil {
		return nil, fmt.Errorf("write backup header: %w", err)
	}
	return ew, nil
}

func (w *encryptWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("write after close")
	}
	written := 0
	for len(p) > 0 {
		n := chunkSize - len(w.buf)
		if n > len(p) {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(w.buf) == chunkSize {
			if err := w.flush(frameData); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (w *encryptWriter) Close() error {
	if w.closed {
		return nil
	}
	if len(w.buf) > 0 {
		if err := w.flush(frameData); err != nil {
			return err
		}
	}
	if err := w.flush(frameFinal); err != nil {
		return err
	}
	w.closed = true
	return nil
}

func (w *encryptWriter) flush(flag byte) error {
	if w.index == ^uint32(0) {
		return fmt.Errorf("backup exceeds encryption frame limit")
	}
	plaintext := w.buf
	if flag == frameFinal {
		plaintext = nil
	}
	nonce := frameNonce(w.prefix, w.index)
	aad := frameAAD(w.prefix, w.index, flag)
	ciphertext := w.aead.Seal(nil, nonce, plaintext, aad)
	header := make([]byte, 5)
	header[0] = flag
	binary.BigEndian.PutUint32(header[1:], uint32(len(ciphertext)))
	if _, err := w.w.Write(header); err != nil {
		return fmt.Errorf("write encrypted frame header: %w", err)
	}
	if _, err := w.w.Write(ciphertext); err != nil {
		return fmt.Errorf("write encrypted frame: %w", err)
	}
	w.index++
	w.buf = w.buf[:0]
	return nil
}

type decryptReader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	prefix [8]byte
	index  uint32
	buf    []byte
	done   bool
}

func newDecryptReader(r *bufio.Reader, key []byte) (*decryptReader, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key")
	}
	header := make([]byte, len(backupMagic)+8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read backup header: %w", err)
	}
	if string(header[:len(backupMagic)]) != string(backupMagic) {
		return nil, fmt.Errorf("backup format is invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize decryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize authentication: %w", err)
	}
	dr := &decryptReader{r: r, aead: aead}
	copy(dr.prefix[:], header[len(backupMagic):])
	return dr, nil
}

func (r *decryptReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if err := r.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *decryptReader) readFrame() error {
	if r.index == ^uint32(0) {
		return fmt.Errorf("backup exceeds encryption frame limit")
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(r.r, header); err != nil {
		return fmt.Errorf("encrypted backup is truncated: %w", err)
	}
	flag := header[0]
	length := binary.BigEndian.Uint32(header[1:])
	if flag != frameData && flag != frameFinal {
		return fmt.Errorf("encrypted backup has invalid frame type")
	}
	if length < uint32(r.aead.Overhead()) || length > uint32(chunkSize+r.aead.Overhead()) {
		return fmt.Errorf("encrypted backup has invalid frame length")
	}
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r.r, ciphertext); err != nil {
		return fmt.Errorf("encrypted backup is truncated: %w", err)
	}
	nonce := frameNonce(r.prefix, r.index)
	aad := frameAAD(r.prefix, r.index, flag)
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return fmt.Errorf("backup authentication failed")
	}
	r.index++
	if flag == frameFinal {
		if len(plaintext) != 0 {
			return fmt.Errorf("encrypted backup has invalid final frame")
		}
		if _, err := r.r.Peek(1); !errors.Is(err, io.EOF) {
			if err == nil {
				return fmt.Errorf("encrypted backup has trailing data")
			}
			return fmt.Errorf("read backup trailer: %w", err)
		}
		r.done = true
		return nil
	}
	if len(plaintext) == 0 {
		return fmt.Errorf("encrypted backup has empty data frame")
	}
	r.buf = plaintext
	return nil
}

func frameNonce(prefix [8]byte, index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix[:])
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce
}

func frameAAD(prefix [8]byte, index uint32, flag byte) []byte {
	aad := make([]byte, 0, len(backupMagic)+8+5)
	aad = append(aad, backupMagic...)
	aad = append(aad, prefix[:]...)
	aad = append(aad, flag)
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	aad = append(aad, indexBytes...)
	return aad
}
