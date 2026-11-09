package vault

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
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

// Params are the Argon2id parameters stored in a vault header.
type Params struct {
	Time, MemoryKiB uint32
	Threads         uint8
}

// DefaultParams are the Argon2id parameters used for new vaults.
var DefaultParams = Params{Time: 3, MemoryKiB: 262144, Threads: 4}

// State is the decrypted vault state.
type State uint8

const (
	StateEmpty  State = 0
	StateLocked State = 1
)

// Progress reports done out of total units of work. It may be nil.
type Progress func(done, total int64)

// Label is the plaintext label stored in the header: readable without the
// password, and authenticated (with the meta block) only when a password is
// used. Treat it as display-only.
type Label struct {
	Owner        string
	Created      time.Time
	LastUnlocked time.Time // zero Time if never
	LastLocked   time.Time // zero Time if never
}

// Vault is an opened vault file. Its methods re-read the header from disk.
type Vault struct {
	path string
	hdr  header
}

// Create writes a new vault of exactly capacity bytes (>= 1 MiB) at path,
// which must not exist. owner (at most 64 bytes of UTF-8 without control
// characters, may be empty; else ErrBadLabel) is stored in the plaintext
// label with the creation time. The data region is filled with random bytes;
// prog reports bytes of filler written. password is zeroed.
func Create(path string, capacity int64, owner string, password []byte, p Params, prog Progress) (err error) {
	defer wipe(password)
	if !validOwner([]byte(owner)) {
		return ErrBadLabel
	}
	if capacity < minCapacity {
		return fmt.Errorf("vault: capacity %d is below the 1 MiB minimum", capacity)
	}
	if err := validateParams(p); err != nil {
		return err
	}
	if len(password) == 0 {
		return errors.New("vault: empty password")
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
		if err != nil {
			_ = removePath(path)
		}
	}()

	h := &header{params: p, capacity: capacity}
	copy(h.label.owner[:], owner)
	h.label.created = time.Now().Unix()
	if err := randRead(h.salt[:]); err != nil {
		return err
	}
	ks, err := deriveKeys(password, h)
	if err != nil {
		return err
	}
	defer ks.wipe()
	m := meta{state: StateEmpty}
	if err := randRead(m.lockSalt[:]); err != nil {
		return err
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	if err := h.sealMeta(ks.meta, nonce, m); err != nil {
		return err
	}
	if _, err := f.WriteAt(h.marshal(), 0); err != nil {
		return err
	}
	if err := fillRandom(f, headerSize, capacity, prog); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != capacity {
		return fmt.Errorf("vault: created file has size %d, want %d", fi.Size(), capacity)
	}
	closed = true
	if err := f.Close(); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// Open reads and validates the header. No password needed.
func Open(path string) (*Vault, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrBadFormat
	}
	h, err := readHeader(f)
	if err != nil {
		return nil, err
	}
	return &Vault{path: path, hdr: *h}, nil
}

// Path returns the vault file path.
func (v *Vault) Path() string { return v.path }

// Capacity returns the vault file size in bytes.
func (v *Vault) Capacity() int64 { return v.hdr.capacity }

// Label returns the plaintext label from the header as last read from disk
// (by Open or by any method that re-reads the header). No password is
// needed; the label is not authenticated until a password is used.
func (v *Vault) Label() Label {
	l := v.hdr.label
	owner := l.owner[:]
	if i := bytes.IndexByte(owner, 0); i >= 0 {
		owner = owner[:i]
	}
	return Label{
		Owner:        string(owner),
		Created:      unixOrZero(l.created),
		LastUnlocked: unixOrZero(l.lastUnlocked),
		LastLocked:   unixOrZero(l.lastLocked),
	}
}

func unixOrZero(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0)
}

// Status decrypts the meta block and returns the state and the stream
// length in bytes. password is zeroed.
func (v *Vault) Status(password []byte) (State, int64, error) {
	defer wipe(password)
	f, err := os.Open(v.path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		return 0, 0, err
	}
	ks, err := deriveKeys(password, h)
	if err != nil {
		return 0, 0, err
	}
	defer ks.wipe()
	m, err := h.openMeta(ks.meta)
	if err != nil {
		return 0, 0, err
	}
	v.hdr = *h
	return m.state, m.usedLen, nil
}

// Lock encrypts folder into the vault, replacing any previous content, and
// verifies it by a full authenticated read-back. The password must match the
// vault's (it is checked against the meta block before anything is written).
//
// Before anything is written, every entry is stat'ed, every regular file is
// opened, special files are refused (*UnsupportedEntryError) and the exact
// stream size is checked against the capacity (ErrTooLarge). A failure after
// writing has started resets the vault to empty and returns *EmptiedError.
//
// After verification the folder is scanned again. If anything was added,
// removed or changed, nothing is deleted and ErrFolderChanged is returned:
// the vault is valid and holds the version from the start of the lock.
// Otherwise, when removeSource is true, exactly the stored entries (plus the
// session marker and macOS "._" companions) are deleted.
//
// prog is called with a single monotonic scale covering both passes:
// total = 2×stream size; the write pass covers the first half and the
// verify pass the second; the last call has done == total.
// password is zeroed.
func (v *Vault) Lock(folder string, password []byte, removeSource bool, prog Progress) error {
	defer wipe(password)
	fi, err := os.Lstat(folder)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("vault: %s is not a directory", folder)
	}
	if isInside(v.path, folder) {
		return errors.New("vault: the vault file is inside the folder to lock")
	}
	ents, err := scanFolder(folder, true)
	if err != nil {
		return err
	}
	plain, err := archiveSize(ents)
	if err != nil {
		return err
	}
	size := streamSize(plain)
	if size > v.hdr.capacity-headerSize {
		return ErrTooLarge
	}
	var token [tokenSize]byte
	if err := randRead(token[:]); err != nil {
		return err
	}
	err = v.lockStream(password, lockJob{
		est:     size,
		produce: func(w io.Writer) error { return writeArchive(w, folder, ents) },
		expect:  ents,
		token:   token,
	}, prog)
	if err != nil {
		return err
	}
	if !folderUnchanged(folder, ents) {
		writeSessionFile(folder, token)
		return ErrFolderChanged
	}
	if !removeSource {
		writeSessionFile(folder, token)
		return nil
	}
	if err := removeRecorded(folder, ents); err != nil {
		return fmt.Errorf("vault: locked and verified, but removing the folder failed: %w", err)
	}
	return nil
}

// lockJob describes one stream for lockStream.
type lockJob struct {
	est     int64                 // ciphertext length (progress only)
	produce func(io.Writer) error // writes the plaintext tar stream
	expect  []recEntry            // entries the stream must contain; nil: not checked
	token   [tokenSize]byte       // session token for the new meta
}

// lockStream writes the plaintext produced by job.produce as a new encrypted
// stream, scrubs the old tail, fsyncs, writes meta, fsyncs, closes and
// verifies through a fresh, uncached read handle. Any failure after the
// first chunk write resets the vault to empty and returns *EmptiedError.
func (v *Vault) lockStream(password []byte, job lockJob, prog Progress) (err error) {
	defer wipe(password)
	f, err := os.OpenFile(v.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	open := true
	defer func() {
		if open {
			f.Close()
		}
	}()
	h, err := readHeader(f)
	if err != nil {
		return err
	}
	ks, err := deriveKeys(password, h)
	if err != nil {
		return err
	}
	defer ks.wipe()
	// Authenticate the password before touching the data region: a typo
	// here must not re-key the vault under the mistyped password.
	old, err := h.openMeta(ks.meta)
	if err != nil {
		return err
	}
	oldEnd := int64(headerSize) + old.usedLen

	m := meta{state: StateLocked, sessionToken: job.token}
	if err := randRead(m.lockSalt[:]); err != nil {
		return err
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	kData, err := deriveSubKey(ks.master, m.lockSalt[:], infoData)
	if err != nil {
		return err
	}
	aead, err := newAEAD(kData)
	wipe(kData)
	if err != nil {
		return err
	}

	est := job.est
	if est < 1 {
		est = 1
	}
	total := 2 * est
	report := func(done int64) {
		if prog != nil {
			prog(done, total)
		}
	}
	report(0)
	cw := newChunkWriter(f, aead, m.lockSalt[:], headerSize, h.capacity, func(written int64) {
		if written > est {
			written = est
		}
		report(written)
	})
	defer cw.wipeBuffers()

	// emptied resets the vault after the old stream was (partly) overwritten
	// and wraps cause. The folder is untouched.
	emptied := func(cause error) error {
		if !open {
			rf, oerr := os.OpenFile(v.path, os.O_RDWR, 0)
			if oerr != nil {
				return errors.Join(&EmptiedError{Cause: cause}, fmt.Errorf("vault: resetting the vault after a failed lock: %w", oerr))
			}
			f, open = rf, true
		}
		// The new chunks are unreadable once their lockSalt is gone; only
		// the remains of the old stream need scrubbing.
		if rerr := v.resetEmpty(f, h, ks.meta, cw.off, oldEnd); rerr != nil {
			return errors.Join(&EmptiedError{Cause: cause}, fmt.Errorf("vault: resetting the vault after a failed lock: %w", rerr))
		}
		return &EmptiedError{Cause: cause}
	}

	err = job.produce(cw)
	if err == nil {
		err = cw.Close()
	}
	if err != nil {
		if cw.touched {
			return emptied(err)
		}
		return err
	}

	newEnd := cw.off
	m.usedLen = cw.written()
	if oldEnd > newEnd {
		if err := fillRandom(f, newEnd, oldEnd, nil); err != nil {
			return emptied(err)
		}
	}
	if err := f.Sync(); err != nil {
		return emptied(err)
	}
	nh := *h
	nh.label.lastLocked = time.Now().Unix()
	if err := nh.sealMeta(ks.meta, nonce, m); err != nil {
		return emptied(err)
	}
	if err := writeMeta(f, &nh); err != nil {
		return emptied(err)
	}
	if err := f.Sync(); err != nil {
		return emptied(err)
	}
	open = false
	if err := f.Close(); err != nil {
		return emptied(err)
	}
	v.hdr = nh

	used := m.usedLen
	err = verifyLocked(v.path, ks, used, job.expect, func(read int64) {
		report(est + int64(float64(read)/float64(used)*float64(est)))
	})
	if err != nil {
		return emptied(fmt.Errorf("vault: verification after lock failed: %w", err))
	}
	report(total)
	return nil
}

// resetEmpty scrubs [from, to) and rewrites meta as an empty vault.
func (v *Vault) resetEmpty(f *os.File, h *header, kMeta []byte, from, to int64) error {
	if to > from {
		if err := fillRandom(f, from, to, nil); err != nil {
			return err
		}
	}
	m := meta{state: StateEmpty}
	if err := randRead(m.lockSalt[:]); err != nil {
		return err
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	nh := *h
	if err := nh.sealMeta(kMeta, nonce, m); err != nil {
		return err
	}
	if err := writeMeta(f, &nh); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	v.hdr = nh
	return nil
}

// verifyLocked opens a new read handle on path (bypassing the OS cache where
// supported), re-reads header and meta, re-derives K_data from the stored
// lockSalt and authenticates the whole stream through a tar reader,
// comparing its entries with expect when that is non-nil.
func verifyLocked(path string, ks *keys, wantUsed int64, expect []recEntry, prog func(int64)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	noCache(f)
	h, err := readHeader(f)
	if err != nil {
		return err
	}
	m, err := h.openMeta(ks.meta)
	if err != nil {
		return err
	}
	if m.state != StateLocked || m.usedLen != wantUsed {
		return fmt.Errorf("%w: meta block does not match what was written", ErrCorrupt)
	}
	cr, err := newStreamReader(f, h, ks, m, prog)
	if err != nil {
		return err
	}
	defer cr.wipeBuffers()
	return validateArchive(cr, expect)
}

func newStreamReader(src io.ReaderAt, h *header, ks *keys, m meta, prog func(int64)) (*chunkReader, error) {
	kData, err := deriveSubKey(ks.master, m.lockSalt[:], infoData)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(kData)
	wipe(kData)
	if err != nil {
		return nil, err
	}
	return newChunkReader(src, aead, m.lockSalt[:], headerSize, m.usedLen, prog), nil
}

// Unlock extracts the stream into destDir, which must not exist. Extraction
// happens in destDir+".partial", which is renamed to destDir only after the
// whole stream has been authenticated, and removed on any failure. Before the
// rename a fresh session token is written both to the meta block (under a
// fresh meta nonce) and, hex-encoded, to sessionFile in the folder root; the
// data region is not modified. prog reports ciphertext bytes processed.
// password is zeroed.
func (v *Vault) Unlock(password []byte, destDir string, prog Progress) (err error) {
	defer wipe(password)
	if _, err := os.Lstat(destDir); err == nil {
		return ErrFolderExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	partial := filepath.Clean(destDir) + ".partial"
	if _, err := os.Lstat(partial); err == nil {
		return fmt.Errorf("vault: %s already exists (left over from an interrupted unlock?); remove it and try again", partial)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	f, err := os.OpenFile(v.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		return err
	}
	ks, err := deriveKeys(password, h)
	if err != nil {
		return err
	}
	defer ks.wipe()
	m, err := h.openMeta(ks.meta)
	if err != nil {
		return err
	}
	v.hdr = *h
	if m.state == StateEmpty {
		return ErrEmpty
	}
	cr, err := newStreamReader(f, h, ks, m, func(read int64) {
		if prog != nil {
			prog(read, m.usedLen)
		}
	})
	if err != nil {
		return err
	}
	defer cr.wipeBuffers()

	if err := os.Mkdir(partial, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			forceRemoveAll(partial)
		}
	}()
	if err := extractArchive(cr, partial); err != nil {
		return err
	}
	if _, err := os.Lstat(destDir); err == nil {
		return ErrFolderExists
	}
	nm := m
	if err := randRead(nm.sessionToken[:]); err != nil {
		return err
	}
	if err := createSessionFile(partial, nm.sessionToken); err != nil {
		return err
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	nh := *h
	nh.label.lastUnlocked = time.Now().Unix()
	if err := nh.sealMeta(ks.meta, nonce, nm); err != nil {
		return err
	}
	if err := writeMeta(f, &nh); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	v.hdr = nh
	return os.Rename(partial, destDir)
}

// FolderMatchesSession reports whether locking folder cannot lose data the
// vault holds: true if the vault is empty, or if folder's sessionFile holds
// the session token in the meta block (the folder came from the latest
// Unlock); false if the vault is locked and the marker is missing or
// different. password is zeroed.
func (v *Vault) FolderMatchesSession(folder string, password []byte) (bool, error) {
	defer wipe(password)
	f, err := os.Open(v.path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		return false, err
	}
	ks, err := deriveKeys(password, h)
	if err != nil {
		return false, err
	}
	defer ks.wipe()
	m, err := h.openMeta(ks.meta)
	if err != nil {
		return false, err
	}
	v.hdr = *h
	if m.state == StateEmpty {
		return true, nil
	}
	tok, ok := readSessionFile(folder)
	return ok && subtle.ConstantTimeCompare(tok[:], m.sessionToken[:]) == 1, nil
}

// createSessionFile writes token, hex-encoded, to a new sessionFile in dir
// (mode 0600).
func createSessionFile(dir string, token [tokenSize]byte) error {
	p := filepath.Join(dir, sessionFile)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(hex.EncodeToString(token[:]))
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeSessionFile replaces the marker in a folder Lock keeps, so the next
// Lock recognises it (best effort).
func writeSessionFile(dir string, token [tokenSize]byte) {
	p := filepath.Join(dir, sessionFile)
	if fi, err := os.Lstat(p); err == nil {
		if !fi.Mode().IsRegular() {
			return
		}
		if removePath(p) != nil {
			return
		}
	}
	_ = createSessionFile(dir, token)
}

// readSessionFile reads the marker in dir; ok is false if it is missing,
// not a regular file or malformed.
func readSessionFile(dir string) (tok [tokenSize]byte, ok bool) {
	p := filepath.Join(dir, sessionFile)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4*tokenSize {
		return tok, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return tok, false
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != tokenSize {
		return tok, false
	}
	copy(tok[:], raw)
	return tok, true
}

// Destroy overwrites the header with random bytes, fsyncs and deletes the file.
func Destroy(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("vault: %s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	buf := make([]byte, headerSize)
	if err := randRead(buf); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteAt(buf, 0); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := removePath(path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// fillRandom writes crypto/rand bytes to [from, to) in 1 MiB writes.
func fillRandom(f io.WriterAt, from, to int64, prog Progress) error {
	const step = 1 << 20
	buf := make([]byte, step)
	total := to - from
	if prog != nil {
		prog(0, total)
	}
	for off := from; off < to; {
		n := int64(step)
		if to-off < n {
			n = to - off
		}
		if err := randRead(buf[:n]); err != nil {
			return err
		}
		if _, err := f.WriteAt(buf[:n], off); err != nil {
			return err
		}
		off += n
		if prog != nil {
			prog(off-from, total)
		}
	}
	return nil
}

// isInside reports whether file lies inside dir (best effort).
func isInside(file, dir string) bool {
	af, err1 := filepath.Abs(file)
	ad, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(af); err == nil {
		af = r
	}
	if r, err := filepath.EvalSymlinks(ad); err == nil {
		ad = r
	}
	rel, err := filepath.Rel(ad, af)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// syncDir fsyncs a directory so a create/remove is durable (best effort,
// not supported on Windows).
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
