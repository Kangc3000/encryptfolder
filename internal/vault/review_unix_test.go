//go:build unix

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Fixed: special files are refused with a typed error before anything is
// written, instead of being skipped and then deleted.
func TestFixedFIFORefused(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "a.txt"), []byte("a"), 0o644)
	fifo := filepath.Join(src, "sub", "pipe")
	os.MkdirAll(filepath.Dir(fifo), 0o755)
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip(err)
	}
	before := fileHash(t, v.Path())
	err := v.Lock(src, pw(), true, nil)
	if !errors.Is(err, ErrUnsupportedEntry) {
		t.Fatalf("got %v, want ErrUnsupportedEntry", err)
	}
	var ue *UnsupportedEntryError
	if !errors.As(err, &ue) || ue.Path != fifo {
		t.Fatalf("got %#v, want path %s", err, fifo)
	}
	if want := "the folder contains a file that cannot be stored (named pipe, socket or device): " + fifo; err.Error() != want {
		t.Fatalf("message %q", err.Error())
	}
	if fileHash(t, v.Path()) != before || !exists(fifo) || !exists(filepath.Join(src, "a.txt")) {
		t.Fatal("vault or folder modified")
	}
}
