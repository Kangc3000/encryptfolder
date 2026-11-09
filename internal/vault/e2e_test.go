package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEndToEndOnDisk runs a full Initialize → Lock → Unlock → Lock → Destroy
// cycle with the production Argon2 parameters in the directory named by
// VAULTLOCK_E2E_DIR (for example a folder on a USB drive). It is skipped
// when the variable is unset so the normal suite stays fast.
func TestEndToEndOnDisk(t *testing.T) {
	dir := os.Getenv("VAULTLOCK_E2E_DIR")
	if dir == "" {
		t.Skip("VAULTLOCK_E2E_DIR not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(dir, "E2E.vault")
	folder := filepath.Join(dir, "E2E")
	_ = os.Remove(vaultPath)
	_ = removeTree(folder)
	t.Cleanup(func() {
		_ = os.Remove(vaultPath)
		_ = removeTree(folder)
		_ = removeTree(folder + ".partial")
	})

	const capacity = 64 << 20
	pw := func() []byte { return []byte("correct horse battery staple") }

	start := time.Now()
	if err := Create(vaultPath, capacity, "Test Owner", pw(), DefaultParams, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Logf("Create %d MiB: %s", capacity>>20, time.Since(start).Round(time.Millisecond))

	// Sample folder: nested dirs, several sizes, one > chunk size, unicode name.
	if err := os.MkdirAll(filepath.Join(folder, "sub", "deeper"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]int{
		"readme.txt":                123,
		"sub/empty.bin":             0,
		"sub/medium.bin":            300_000,
		"sub/deeper/big.bin":        20 << 20,
		"sub/deeper/文件-ünïcode.dat": 4096,
	}
	for name, size := range files {
		b := make([]byte, size)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := hashTree(t, folder)

	start = time.Now()
	v, err := Open(vaultPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Lock(folder, pw(), true, nil); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	t.Logf("Lock ~20 MiB: %s", time.Since(start).Round(time.Millisecond))
	if _, err := os.Stat(folder); !os.IsNotExist(err) {
		t.Fatalf("plain folder still present after Lock: %v", err)
	}
	if fi, err := os.Stat(vaultPath); err != nil || fi.Size() != capacity {
		t.Fatalf("vault size changed: %v %d", err, fi.Size())
	}

	if err := v.Unlock([]byte("wrong password"), folder, nil); err != ErrWrongPassword {
		t.Fatalf("wrong password: got %v", err)
	}
	if _, err := os.Stat(folder); !os.IsNotExist(err) {
		t.Fatalf("folder appeared after failed unlock")
	}

	start = time.Now()
	if err := v.Unlock(pw(), folder, nil); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	t.Logf("Unlock: %s", time.Since(start).Round(time.Millisecond))
	after := hashTree(t, folder)
	if !bytes.Equal(before, after) {
		t.Fatal("folder contents differ after round trip")
	}
	if ok, err := v.FolderMatchesSession(folder, pw()); err != nil || !ok {
		t.Fatalf("FolderMatchesSession after Unlock: %v %v", ok, err)
	}

	// Lock a second time (exercises tail overwrite), then destroy.
	start = time.Now()
	if err := v.Lock(folder, pw(), true, nil); err != nil {
		t.Fatalf("second Lock: %v", err)
	}
	t.Logf("second Lock: %s", time.Since(start).Round(time.Millisecond))
	if _, err := os.Lstat(folder); !os.IsNotExist(err) {
		t.Fatalf("plain folder still present after second Lock: %v", err)
	}
	if err := Destroy(vaultPath); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(vaultPath); !os.IsNotExist(err) {
		t.Fatal("vault still exists after Destroy")
	}
}

func hashTree(t *testing.T, root string) []byte {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		// The session marker (written by Unlock) and macOS "._" companions
		// on exFAT are not folder content.
		if rel == sessionFile || isAppleDouble(p, d) {
			return nil
		}
		h.Write([]byte(rel))
		if d.IsDir() {
			h.Write([]byte{'/'})
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return h.Sum(nil)
}
