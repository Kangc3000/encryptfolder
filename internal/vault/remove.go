package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/text/unicode/norm"
)

// removeTree deletes dir and everything inside it.
//
// It exists because os.RemoveAll is not reliable on every filesystem this
// program runs on. macOS's exFAT driver lists names containing accented or
// non-Latin characters in Unicode NFD form but only accepts the originally
// written (usually NFC) bytes for unlink, so os.RemoveAll gets ENOENT for
// those entries, ignores it, and then fails with "directory not empty".
// removeTree retries each deletion with the NFC and NFD spellings of the
// name, and retries a non-empty directory a few times because macOS can
// create "._name" metadata files inside it concurrently.
func removeTree(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fi.IsDir() {
		return removePath(dir)
	}
	return removeDir(dir)
}

func removeDir(dir string) error {
	const attempts = 5
	for attempt := 1; ; attempt++ {
		ents, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			// Directory may be read-only; make it writable and try again.
			_ = os.Chmod(dir, 0o700)
			if ents, err = os.ReadDir(dir); err != nil {
				return err
			}
		}
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				err = removeDir(p)
			} else {
				err = removePath(p)
			}
			if err != nil {
				return err
			}
		}
		err = removePath(dir)
		if err == nil {
			return nil
		}
		if !isNotEmpty(err) || attempt >= attempts {
			return err
		}
		time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
	}
}

// removePath removes one file, symlink or empty directory, trying the
// listed name first and then its NFC and NFD spellings.
func removePath(p string) error {
	err := os.Remove(p)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir, base := filepath.Split(p)
	for _, alt := range []string{norm.NFC.String(base), norm.NFD.String(base)} {
		if alt == base {
			continue
		}
		err2 := os.Remove(filepath.Join(dir, alt))
		if err2 == nil || !errors.Is(err2, fs.ErrNotExist) {
			return err2
		}
	}
	// Every spelling reports "not found". Believe it only if a stat agrees.
	if _, serr := os.Lstat(p); errors.Is(serr, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove %s: entry is listed but cannot be deleted: %w", p, err)
}

func isNotEmpty(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOTEMPTY || errno == syscall.EEXIST
	}
	return false
}

// RemoveFolder deletes a plain folder (and the "._name" metadata file macOS
// may have left beside it) using the same filesystem-tolerant deletion that
// Lock uses. The UI calls it for Reset; it never touches vault files.
func RemoveFolder(path string) error {
	if err := removeTree(path); err != nil {
		return err
	}
	removeAppleDouble(path)
	return nil
}

// removeAppleDouble deletes the "._name" metadata file that macOS creates
// next to name on exFAT and FAT volumes, if there is one.
func removeAppleDouble(name string) {
	dir, base := filepath.Split(name)
	_ = removePath(filepath.Join(dir, "._"+base))
}
