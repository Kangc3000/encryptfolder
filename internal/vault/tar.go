package vault

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// writeArchive writes a PAX tar of the recorded entries of folder to w,
// in the recorded order and with the recorded metadata (only permission
// bits and whole-second mtimes; no owners). Each regular file contributes
// exactly its recorded size: a file that grew is cut at that size (Lock's
// final rescan then reports the change), a file that shrank is an error.
func writeArchive(w io.Writer, folder string, ents []recEntry) error {
	tw := tar.NewWriter(w)
	for i := range ents {
		e := &ents[i]
		if err := tw.WriteHeader(e.tarHeader()); err != nil {
			return err
		}
		if e.typ == tar.TypeReg {
			if err := copyFileInto(tw, filepath.Join(folder, filepath.FromSlash(e.rel)), e.size); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

func copyFileInto(w io.Writer, path string, size int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return err
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("vault: %s is no longer a regular file", path)
	}
	if _, err := io.CopyN(w, f, size); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("vault: %s shrank while locking", path)
		}
		return err
	}
	return nil
}

// streamErr maps an error from the tar reader: errors originating in the
// chunk reader (authentication, I/O) are returned unchanged; anything else
// means the authenticated plaintext is not a valid archive.
func streamErr(cr *chunkReader, err error) error {
	if cr.err != nil {
		return cr.err
	}
	return fmt.Errorf("%w: invalid archive: %v", ErrCorrupt, err)
}

// tarBody wraps a tar.Reader so that read errors are classified by
// streamErr, while write errors on the destination pass through io.Copy
// untouched.
type tarBody struct {
	tr *tar.Reader
	cr *chunkReader
}

func (b tarBody) Read(p []byte) (int, error) {
	n, err := b.tr.Read(p)
	if err != nil && err != io.EOF {
		err = streamErr(b.cr, err)
	}
	return n, err
}

// validateArchive reads the whole stream through a tar reader, discarding
// the data, so that every chunk is authenticated and the archive parses.
// When expect is non-nil the entries read back (name, type, size, symlink
// target) must match it exactly.
func validateArchive(cr *chunkReader, expect []recEntry) error {
	tr := tar.NewReader(cr)
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return streamErr(cr, err)
		}
		if expect != nil {
			if n >= len(expect) {
				return fmt.Errorf("%w: archive has an unexpected extra entry %q", ErrCorrupt, hdr.Name)
			}
			if err := matchEntry(hdr, &expect[n]); err != nil {
				return err
			}
		}
		n++
		if _, err := io.Copy(io.Discard, tarBody{tr, cr}); err != nil {
			return err
		}
	}
	if expect != nil && n != len(expect) {
		return fmt.Errorf("%w: archive has %d entries, %d were written", ErrCorrupt, n, len(expect))
	}
	return cr.drain()
}

func matchEntry(hdr *tar.Header, e *recEntry) error {
	name := strings.TrimSuffix(hdr.Name, "/")
	ok := name == e.rel && hdr.Typeflag == e.typ
	switch e.typ {
	case tar.TypeReg:
		ok = ok && hdr.Size == e.size
	case tar.TypeSymlink:
		ok = ok && hdr.Linkname == e.link
	}
	if !ok {
		return fmt.Errorf("%w: archive entry %q does not match what was written (%q)", ErrCorrupt, hdr.Name, e.rel)
	}
	return nil
}

func errUnsafe(name, why string) error {
	return fmt.Errorf("%w: unsafe archive entry %q: %s", ErrCorrupt, name, why)
}

// safeRelPath validates a tar entry name and returns it as a cleaned,
// OS-specific relative path ("." for the archive root).
func safeRelPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", errUnsafe(name, "empty or invalid name")
	}
	if strings.HasPrefix(name, "/") {
		return "", errUnsafe(name, "absolute path")
	}
	p := filepath.FromSlash(strings.TrimRight(name, "/"))
	if filepath.Clean(p) == "." {
		return ".", nil
	}
	if !filepath.IsLocal(p) {
		return "", errUnsafe(name, "path escapes the destination")
	}
	return filepath.Clean(p), nil
}

// ensureParents creates the missing parent directories of rel under root,
// refusing to traverse anything that is not a real directory (in particular
// a symlink created by an earlier entry).
func ensureParents(root, rel, name string) error {
	dir := filepath.Dir(rel)
	if dir == "." {
		return nil
	}
	cur := root
	for _, part := range strings.Split(dir, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(cur, 0o700); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return errUnsafe(name, "parent is not a directory")
		}
	}
	return nil
}

type dirMeta struct {
	path  string
	mode  fs.FileMode
	mtime time.Time
}

// extractArchive extracts the tar stream from cr into dest, which must be an
// existing empty directory. Directory modes and mtimes are applied only after
// the whole stream has been authenticated.
func extractArchive(cr *chunkReader, dest string) error {
	tr := tar.NewReader(cr)
	var dirs []dirMeta
	// Case-folded name (and every parent prefix) → first spelling seen.
	seen := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return streamErr(cr, err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeReg, tar.TypeSymlink:
		default:
			continue // hard links, devices, PAX globals, …: skipped
		}
		rel, err := safeRelPath(hdr.Name)
		if err != nil {
			return err
		}
		if rel == "." {
			continue
		}
		if err := checkCase(seen, filepath.ToSlash(rel)); err != nil {
			return err
		}
		if err := ensureParents(dest, rel, hdr.Name); err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		mode := fs.FileMode(hdr.Mode) & fs.ModePerm
		switch hdr.Typeflag {
		case tar.TypeDir:
			fi, err := os.Lstat(target)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				if err := os.Mkdir(target, 0o700); err != nil {
					return err
				}
			case err != nil:
				return err
			case !fi.IsDir():
				return errUnsafe(hdr.Name, "directory collides with another entry")
			}
			dirs = append(dirs, dirMeta{target, mode, hdr.ModTime})
		case tar.TypeReg:
			if err := extractFile(target, tarBody{tr, cr}, mode, hdr.ModTime); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if hdr.Linkname == "" {
				return errUnsafe(hdr.Name, "empty symlink target")
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				// Creating symlinks on Windows needs Developer Mode or
				// admin rights; skip them there rather than fail.
				if runtime.GOOS != "windows" {
					return err
				}
			}
		}
	}
	if err := cr.drain(); err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
		if err := os.Chtimes(d.path, d.mtime, d.mtime); err != nil {
			return err
		}
	}
	return nil
}

// checkCase records rel and all its parent prefixes in seen, keyed by their
// lower-case form, and fails if one of them was seen with another spelling.
func checkCase(seen map[string]string, rel string) error {
	for p := rel; ; {
		key := strings.ToLower(p)
		if prev, ok := seen[key]; ok {
			if prev != p {
				return &CaseCollisionError{A: prev, B: p}
			}
		} else {
			seen[key] = p
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return nil
		}
		p = p[:i]
	}
}

func extractFile(target string, src io.Reader, mode fs.FileMode, mtime time.Time) error {
	// O_EXCL: never overwrite or follow an existing entry (including a symlink).
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(target, mode); err != nil {
		return err
	}
	return os.Chtimes(target, mtime, mtime)
}

// forceRemoveAll removes dir, making directories writable first if needed.
func forceRemoveAll(dir string) {
	if removeTree(dir) == nil {
		return
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	_ = removeTree(dir)
}
