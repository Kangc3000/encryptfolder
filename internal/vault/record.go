package vault

import (
	"archive/tar"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sessionFile is the marker Unlock writes in the root of the extracted
// folder. Lock never stores it but deletes it with the folder.
const sessionFile = ".vaultlock-session"

// recEntry records one folder entry exactly as Lock stores it.
type recEntry struct {
	rel   string // '/'-separated path relative to the folder root
	typ   byte   // tar.TypeDir, tar.TypeReg or tar.TypeSymlink
	perm  fs.FileMode
	size  int64 // regular files only
	mtime int64 // Unix seconds
	link  string
}

// tarHeader returns the header writeArchive emits for e.
func (e *recEntry) tarHeader() *tar.Header {
	h := &tar.Header{
		Name:     e.rel,
		Typeflag: e.typ,
		Mode:     int64(e.perm),
		ModTime:  time.Unix(e.mtime, 0),
		Format:   tar.FormatPAX,
	}
	switch e.typ {
	case tar.TypeDir:
		h.Name += "/"
	case tar.TypeReg:
		h.Size = e.size
	case tar.TypeSymlink:
		h.Linkname = e.link
	}
	return h
}

// sameAs reports whether f (a later scan of the same path) is unchanged.
// Directory mtimes are not compared: they change whenever an entry is
// added or removed (including tolerated "._" files), and such changes are
// detected through the entries themselves.
func (e *recEntry) sameAs(f *recEntry) bool {
	if e.rel != f.rel || e.typ != f.typ {
		return false
	}
	switch e.typ {
	case tar.TypeReg:
		return e.size == f.size && e.mtime == f.mtime
	case tar.TypeSymlink:
		return e.link == f.link && e.mtime == f.mtime
	}
	return true
}

// isAppleDouble reports whether p is a "._name" metadata file that macOS
// created next to an existing sibling "name" (on exFAT and FAT volumes).
func isAppleDouble(p string, d fs.DirEntry) bool {
	base := d.Name()
	if len(base) <= 2 || !strings.HasPrefix(base, "._") || !d.Type().IsRegular() {
		return false
	}
	_, err := os.Lstat(filepath.Join(filepath.Dir(p), base[2:]))
	return err == nil
}

// scanFolder walks folder in lexical order and records every entry Lock
// stores: directories, regular files and symlinks, excluding the session
// marker in the root and tolerated AppleDouble files. Any other file type
// fails with *UnsupportedEntryError. When probe is true every regular file
// is also opened for reading (and closed) so permission problems surface
// before anything is written.
func scanFolder(folder string, probe bool) ([]recEntry, error) {
	var ents []recEntry
	err := filepath.WalkDir(folder, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == folder {
			return nil
		}
		rel, err := filepath.Rel(folder, p)
		if err != nil {
			return err
		}
		if rel == sessionFile || isAppleDouble(p, d) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		e := recEntry{
			rel:   filepath.ToSlash(rel),
			perm:  mode.Perm(),
			mtime: info.ModTime().Unix(),
		}
		switch {
		case mode.IsDir():
			e.typ = tar.TypeDir
		case mode.IsRegular():
			e.typ = tar.TypeReg
			e.size = info.Size()
			if probe {
				f, err := os.Open(p)
				if err != nil {
					return err
				}
				f.Close()
			}
		case mode&fs.ModeSymlink != 0:
			e.typ = tar.TypeSymlink
			if e.link, err = os.Readlink(p); err != nil {
				return err
			}
		default:
			return &UnsupportedEntryError{Path: p}
		}
		ents = append(ents, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ents, nil
}

// countWriter counts bytes and discards them.
type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// archiveSize returns the exact length of the tar stream writeArchive
// produces for ents: every header (including PAX extended headers) is
// encoded by a real tar.Writer into a byte counter, file data is counted as
// its size rounded up to 512 without reading it, then the trailer.
func archiveSize(ents []recEntry) (int64, error) {
	var total int64
	for i := range ents {
		var c countWriter
		if err := tar.NewWriter(&c).WriteHeader(ents[i].tarHeader()); err != nil {
			return 0, err
		}
		total += c.n
		if ents[i].typ == tar.TypeReg {
			total += (ents[i].size + 511) / 512 * 512
		}
	}
	var c countWriter
	if err := tar.NewWriter(&c).Close(); err != nil {
		return 0, err
	}
	return total + c.n, nil
}

// folderUnchanged rescans folder and reports whether it still matches ents.
func folderUnchanged(folder string, ents []recEntry) bool {
	now, err := scanFolder(folder, false)
	if err != nil || len(now) != len(ents) {
		return false
	}
	for i := range ents {
		if !ents[i].sameAs(&now[i]) {
			return false
		}
	}
	return true
}

// removeRecorded deletes exactly the recorded entries of folder, the
// session marker, the folder itself and the AppleDouble companions of all of
// them. Anything not recorded makes the deletion of its directory fail.
func removeRecorded(folder string, ents []recEntry) error {
	// Names whose "._" companions may be deleted, per directory.
	known := map[string]map[string]bool{}
	addKnown := func(p string) {
		dir, base := filepath.Split(p)
		dir = filepath.Clean(dir)
		if known[dir] == nil {
			known[dir] = map[string]bool{}
		}
		known[dir][base] = true
	}
	root := filepath.Clean(folder)
	addKnown(filepath.Join(root, sessionFile))
	for i := range ents {
		addKnown(filepath.Join(root, filepath.FromSlash(ents[i].rel)))
	}

	for i := range ents {
		if ents[i].typ == tar.TypeDir {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(ents[i].rel))
		if err := removeEntry(p); err != nil {
			return err
		}
		removeAppleDouble(p)
	}
	marker := filepath.Join(root, sessionFile)
	if err := removeEntry(marker); err != nil {
		return err
	}
	removeAppleDouble(marker)
	// WalkDir order is pre-order, so walking it backwards removes every
	// directory before its parent.
	for i := len(ents) - 1; i >= 0; i-- {
		if ents[i].typ != tar.TypeDir {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(ents[i].rel))
		if err := removeRecordedDir(p, known[p]); err != nil {
			return err
		}
		removeAppleDouble(p)
	}
	if err := removeRecordedDir(root, known[root]); err != nil {
		return err
	}
	removeAppleDouble(root)
	return nil
}

// removeEntry removes one file, symlink or empty directory, making it (and
// its parent) writable and retrying once if the first attempt is refused.
func removeEntry(p string) error {
	err := removePath(p)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	_ = os.Chmod(filepath.Dir(p), 0o700)
	if fi, lerr := os.Lstat(p); lerr == nil && fi.Mode()&fs.ModeSymlink == 0 {
		_ = os.Chmod(p, fi.Mode().Perm()|0o600)
	}
	return removePath(p)
}

// removeRecordedDir removes the (otherwise empty) directory dir. If it is
// not empty only because macOS left or recreated "._name" companions of
// names in known, those are deleted and the removal is retried.
func removeRecordedDir(dir string, known map[string]bool) error {
	const attempts = 5
	for attempt := 1; ; attempt++ {
		err := removeEntry(dir)
		if err == nil || !isNotEmpty(err) || attempt >= attempts {
			if err != nil && isNotEmpty(err) {
				return fmt.Errorf("%s contains files that were not locked: %w", dir, err)
			}
			return err
		}
		ents, rerr := os.ReadDir(dir)
		if rerr != nil {
			return err
		}
		for _, e := range ents {
			name := e.Name()
			if strings.HasPrefix(name, "._") && e.Type().IsRegular() && known[name[2:]] {
				if err := removePath(filepath.Join(dir, name)); err != nil {
					return err
				}
			}
		}
		time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
	}
}
