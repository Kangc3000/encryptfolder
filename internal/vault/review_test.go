package vault

// Tests written during security review. Tests named TestFixed* reproduce an
// issue found in review and PASS only when it is fixed.

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func lockRaw(t *testing.T, v *Vault, ents []tarEnt) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644, Format: tar.FormatPAX}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		io.WriteString(tw, e.body)
	}
	tw.Close()
	if err := lockBytes(v, buf.Bytes()); err != nil {
		t.Fatalf("lockStream: %v", err)
	}
}

// archiveNames decrypts the vault's stream and returns the tar entry names.
func archiveNames(t *testing.T, v *Vault) []string {
	t.Helper()
	f, err := os.Open(v.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := readHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := deriveKeys(pw(), h)
	if err != nil {
		t.Fatal(err)
	}
	m, err := h.openMeta(ks.meta)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := newStreamReader(f, h, ks, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(cr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// oldEstimate is the pre-fix, PAX-blind estimate.
func oldEstimate(t *testing.T, folder string) int64 {
	t.Helper()
	ents, err := scanFolder(folder, false)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(1024)
	for _, e := range ents {
		total += 512 + (e.size+511)/512*512
	}
	return total
}

// Fixed: the capacity pre-check counts PAX extended headers exactly, so a
// folder of non-ASCII names that the old estimate let through is refused
// before anything is written and the previous content survives.
func TestFixedPAXEstimate(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "precious.txt"), []byte("only encrypted copy"), 0o644)
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3000; i++ {
		writeFile(t, filepath.Join(src, fmt.Sprintf("résumé-%05d.txt", i)), nil, 0o644)
	}
	if est := streamSize(oldEstimate(t, src)); est > testCap-headerSize {
		t.Fatalf("test setup: old estimate %d already exceeds capacity", est)
	}
	before := fileHash(t, v.Path())
	err := v.Lock(src, pw(), true, nil)
	if !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrVaultEmptied) {
		t.Fatalf("got %v, want plain ErrTooLarge", err)
	}
	if fileHash(t, v.Path()) != before {
		t.Fatal("vault modified by a rejected Lock")
	}
	if !exists(filepath.Join(src, "résumé-02999.txt")) {
		t.Fatal("folder touched")
	}
	out := filepath.Join(dir, "Out")
	if err := v.Unlock(pw(), out, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "precious.txt")); string(b) != "only encrypted copy" {
		t.Fatal("previous content lost")
	}
}

// The pre-computed size equals the real stream, including PAX headers for
// long and non-ASCII names.
func TestArchiveSizeExact(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	buildTree(t, src)
	long := strings.Repeat("long-directory-name-", 6)
	writeFile(t, filepath.Join(src, long, strings.Repeat("ñ", 80)+".txt"), randBytes(t, 1000), 0o644)
	if err := os.Symlink(strings.Repeat("target/", 30), filepath.Join(src, "long-link")); err != nil {
		t.Fatal(err)
	}
	ents, err := scanFolder(src, true)
	if err != nil {
		t.Fatal(err)
	}
	want, err := archiveSize(ents)
	if err != nil {
		t.Fatal(err)
	}
	var c countWriter
	if err := writeArchive(&c, src, ents); err != nil {
		t.Fatal(err)
	}
	if c.n != want {
		t.Fatalf("archiveSize %d, real stream %d", want, c.n)
	}
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	if _, used, _ := v.Status(pw()); used != streamSize(want) {
		t.Fatalf("usedLen %d, predicted %d", used, streamSize(want))
	}
}

// Fixed: an unreadable file is found by the pre-walk, before the vault is
// touched, so the previous content survives.
func TestFixedUnreadableFileRefusedBeforeWriting(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "precious.txt"), []byte("old"), 0o644)
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "a-big.bin"), randBytes(t, 200<<10), 0o644)
	writeFile(t, filepath.Join(src, "z-locked.txt"), []byte("x"), 0o000)
	defer os.Chmod(filepath.Join(src, "z-locked.txt"), 0o644)
	before := fileHash(t, v.Path())
	err := v.Lock(src, pw(), true, nil)
	if !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrVaultEmptied) {
		t.Fatalf("got %v, want a permission error before writing", err)
	}
	if fileHash(t, v.Path()) != before {
		t.Fatal("vault modified")
	}
	if st, _, _ := v.Status(pw()); st != StateLocked {
		t.Fatalf("state %v, want locked", st)
	}
}

// A failure after writing started resets the vault and says so.
func TestEmptiedError(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "f.txt"), []byte("x"), 0o644)
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("disk on fire")
	err := v.lockStream(pw(), lockJob{est: 300 << 10, produce: func(w io.Writer) error {
		if _, err := w.Write(make([]byte, 200<<10)); err != nil {
			return err
		}
		return cause
	}}, nil)
	if !errors.Is(err, ErrVaultEmptied) || !errors.Is(err, cause) || errors.Unwrap(err) != cause || errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	want := "the lock failed and the vault's previous locked copy had to be cleared; the folder is untouched: disk on fire"
	if err.Error() != want {
		t.Fatalf("message %q", err.Error())
	}
	if st, used, err := v.Status(pw()); err != nil || st != StateEmpty || used != 0 {
		t.Fatalf("after failure: %v %v %v", st, used, err)
	}

	// An error before the first chunk write leaves the vault alone.
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	before := fileHash(t, v.Path())
	err = v.lockStream(pw(), lockJob{est: 1, produce: func(w io.Writer) error { return cause }}, nil)
	if err != cause || fileHash(t, v.Path()) != before {
		t.Fatalf("early failure: %v (vault changed: %v)", err, fileHash(t, v.Path()) != before)
	}
}

func TestChunkWriterWipe(t *testing.T) {
	aead, _ := newAEAD(make([]byte, keySize))
	cw := newChunkWriter(failWriterAt{}, aead, nil, 0, 1<<30, nil)
	secret := bytes.Repeat([]byte{0xAA}, chunkSize+10)
	if _, err := cw.Write(secret); err == nil {
		t.Fatal("write succeeded")
	}
	cw.wipeBuffers()
	if !bytes.Equal(cw.buf[:cap(cw.buf)], make([]byte, chunkSize)) {
		t.Fatal("plaintext buffer not wiped")
	}
}

type failWriterAt struct{}

func (failWriterAt) WriteAt([]byte, int64) (int, error) { return 0, errors.New("write failed") }

// The verify pass compares the entries read back with what was written.
func TestVerifyEntryMismatch(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "a.txt"), []byte("aaa"), 0o644)
	ents, err := scanFolder(src, true)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]recEntry(nil), ents...)
	wrong[0].size++
	err = v.lockStream(pw(), lockJob{est: 1, produce: func(w io.Writer) error { return writeArchive(w, src, ents) }, expect: wrong}, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
	extra := append(append([]recEntry(nil), ents...), recEntry{rel: "b.txt", typ: tar.TypeReg})
	err = v.lockStream(pw(), lockJob{est: 1, produce: func(w io.Writer) error { return writeArchive(w, src, ents) }, expect: extra}, nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing entry: got %v, want ErrCorrupt", err)
	}
	if !exists(filepath.Join(src, "a.txt")) {
		t.Fatal("folder touched")
	}
}

// Fixed: a file created during the verify pass makes Lock keep the folder.
// The vault is valid and holds the version from the start of the lock.
func TestFixedFileWrittenDuringLockKept(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "doc.txt"), randBytes(t, 300<<10), 0o644)
	created := false
	prog := func(done, total int64) {
		if !created && done*2 > total { // verify pass
			created = true
			os.WriteFile(filepath.Join(src, "autosave.txt"), []byte("new work"), 0o644)
		}
	}
	err := v.Lock(src, pw(), true, prog)
	if !created {
		t.Fatal("callback never fired in verify pass")
	}
	if !errors.Is(err, ErrFolderChanged) {
		t.Fatalf("got %v, want ErrFolderChanged", err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, "autosave.txt")); string(b) != "new work" {
		t.Fatal("autosave.txt lost")
	}
	if !exists(filepath.Join(src, "doc.txt")) {
		t.Fatal("doc.txt deleted")
	}
	out := filepath.Join(dir, "Out")
	if err := v.Unlock(pw(), out, nil); err != nil {
		t.Fatalf("vault not valid: %v", err)
	}
	if exists(filepath.Join(out, "autosave.txt")) || !exists(filepath.Join(out, "doc.txt")) {
		t.Fatal("vault does not hold the version from the start of the lock")
	}
}

// A file modified during the write pass (after it was stored) is detected.
func TestFileModifiedDuringLockKept(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "a.txt"), []byte("original"), 0o644)
	writeFile(t, filepath.Join(src, "b.bin"), randBytes(t, 300<<10), 0o644)
	changed := false
	prog := func(done, total int64) {
		if !changed && done > 0 && done*2 < total { // write pass
			changed = true
			os.WriteFile(filepath.Join(src, "a.txt"), []byte("edited!!"), 0o644) // same size
			future := time.Now().Add(time.Hour)
			os.Chtimes(filepath.Join(src, "a.txt"), future, future)
		}
	}
	err := v.Lock(src, pw(), true, prog)
	if !changed {
		t.Fatal("callback never fired in write pass")
	}
	if !errors.Is(err, ErrFolderChanged) {
		t.Fatalf("got %v, want ErrFolderChanged", err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, "a.txt")); string(b) != "edited!!" {
		t.Fatal("edited file lost")
	}
	// The kept folder carries a marker matching the vault.
	if ok, err := v.FolderMatchesSession(src, pw()); err != nil || !ok {
		t.Fatalf("kept folder: %v %v, want true", ok, err)
	}
	out := filepath.Join(dir, "Out")
	if err := v.Unlock(pw(), out, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "a.txt")); string(b) != "original" {
		t.Fatalf("vault holds %q", b)
	}
	// out was unlocked last, so src no longer matches.
	if ok, err := v.FolderMatchesSession(src, pw()); err != nil || ok {
		t.Fatalf("FolderMatchesSession(src) = %v, %v; want false after a later unlock", ok, err)
	}
}

// Nothing changed: the folder is deleted, and nothing next to it.
func TestLockUnchangedDeletesFolder(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	buildTree(t, src)
	writeFile(t, filepath.Join(dir, "Test-sibling.txt"), []byte("keep"), 0o644)
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	if exists(src) {
		t.Fatal("folder kept")
	}
	if !exists(filepath.Join(dir, "Test-sibling.txt")) || !exists(v.Path()) {
		t.Fatal("something outside the folder was deleted")
	}
}

// "._x" AppleDouble files next to x are neither stored nor treated as a
// change, and are deleted with the folder; a "._y" without y is stored.
func TestAppleDoubleIgnored(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "x.txt"), []byte("x"), 0o644)
	writeFile(t, filepath.Join(src, "._x.txt"), []byte("metadata"), 0o644)
	writeFile(t, filepath.Join(src, "sub", "big.bin"), randBytes(t, 300<<10), 0o644)
	writeFile(t, filepath.Join(src, "._orphan"), []byte("user file"), 0o644)
	created := false
	prog := func(done, total int64) {
		if !created && done*2 > total { // verify pass: macOS adds a companion
			created = true
			os.WriteFile(filepath.Join(src, "sub", "._big.bin"), []byte("md"), 0o644)
			os.WriteFile(filepath.Join(src, "._sub"), []byte("md"), 0o644)
		}
	}
	if err := v.Lock(src, pw(), true, prog); err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("callback never fired")
	}
	if exists(src) {
		t.Fatal("folder kept")
	}
	names := archiveNames(t, v)
	if contains(names, "._x.txt") || contains(names, "sub/._big.bin") || !contains(names, "._orphan") || !contains(names, "x.txt") {
		t.Fatalf("archive entries %v", names)
	}
}

// Session marker: written by Unlock, checked by FolderMatchesSession, never
// stored by Lock, deleted with the folder.
func TestSessionMarker(t *testing.T) {
	v, dir := newTestVault(t)
	if ok, err := v.FolderMatchesSession(filepath.Join(dir, "none"), pw()); err != nil || !ok {
		t.Fatalf("empty vault: %v %v, want true", ok, err)
	}
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "f.txt"), []byte("hello"), 0o644)
	if ok, err := v.FolderMatchesSession(src, pw()); err != nil || !ok {
		t.Fatalf("empty vault, folder without marker: %v %v, want true", ok, err)
	}
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	hd1, m1 := readMeta(t, v.Path())
	img1, _ := os.ReadFile(v.Path())

	if err := v.Unlock(pw(), src, nil); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(src, sessionFile)
	fi, err := os.Lstat(marker)
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("marker mode %v", fi.Mode().Perm())
	}
	h2, m2 := readMeta(t, v.Path())
	if b, _ := os.ReadFile(marker); string(b) != fmt.Sprintf("%x", m2.sessionToken) {
		t.Fatalf("marker %q does not hold the meta token", b)
	}
	if m2.sessionToken == m1.sessionToken || m2.lockSalt != m1.lockSalt || m2.usedLen != m1.usedLen {
		t.Fatal("unlock should change only the session token")
	}
	if m2.state != StateLocked {
		t.Fatal("state changed")
	}
	if h2.nonce == hd1.nonce {
		t.Fatal("meta nonce not refreshed")
	}
	img2, _ := os.ReadFile(v.Path())
	if !bytes.Equal(img1[headerSize:], img2[headerSize:]) {
		t.Fatal("unlock modified the data region")
	}

	p := pw()
	if ok, err := v.FolderMatchesSession(src, p); err != nil || !ok {
		t.Fatalf("after unlock: %v %v, want true", ok, err)
	}
	if !bytes.Equal(p, make([]byte, len(p))) {
		t.Error("password not zeroed")
	}
	if _, err := v.FolderMatchesSession(src, wrongPW()); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}

	// A folder from an older unlock does not match.
	other := filepath.Join(dir, "Other")
	if err := v.Unlock(pw(), other, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := v.FolderMatchesSession(src, pw()); ok {
		t.Fatal("stale marker matched")
	}
	if ok, _ := v.FolderMatchesSession(other, pw()); !ok {
		t.Fatal("fresh marker did not match")
	}
	removeTree(other)

	// Lock excludes the marker from the archive and deletes it.
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	if exists(src) {
		t.Fatal("folder (with marker) not removed")
	}
	if names := archiveNames(t, v); contains(names, sessionFile) || !contains(names, "f.txt") {
		t.Fatalf("archive entries %v", names)
	}

	// Missing marker → false.
	if err := v.Unlock(pw(), src, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if ok, err := v.FolderMatchesSession(src, pw()); err != nil || ok {
		t.Fatalf("missing marker: %v %v, want false", ok, err)
	}
	// A folder kept by Lock gets a matching marker.
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := v.FolderMatchesSession(src, pw()); err != nil || !ok {
		t.Fatalf("kept folder: %v %v, want true", ok, err)
	}
}

// Fixed: names differing only by case give a typed, friendly error on every
// filesystem, and nothing is left behind.
func TestFixedCaseCollision(t *testing.T) {
	cases := []struct {
		ents []tarEnt
		a, b string
	}{
		{[]tarEnt{
			{name: "README.txt", typ: tar.TypeReg, body: "one"},
			{name: "readme.txt", typ: tar.TypeReg, body: "two"},
		}, "README.txt", "readme.txt"},
		{[]tarEnt{
			{name: "Dir/a.txt", typ: tar.TypeReg, body: "one"},
			{name: "dir/b.txt", typ: tar.TypeReg, body: "two"},
		}, "Dir", "dir"},
	}
	for _, c := range cases {
		v, dir := newTestVault(t)
		lockRaw(t, v, c.ents)
		err := v.Unlock(pw(), filepath.Join(dir, "Out"), nil)
		if !errors.Is(err, ErrCaseCollision) {
			t.Fatalf("got %v, want ErrCaseCollision", err)
		}
		var ce *CaseCollisionError
		if !errors.As(err, &ce) || ce.A != c.a || ce.B != c.b {
			t.Fatalf("got %#v", err)
		}
		want := "the vault contains two names that differ only by letter case, which this disk cannot store: " + c.a + " and " + c.b
		if err.Error() != want {
			t.Fatalf("message %q", err.Error())
		}
		if exists(filepath.Join(dir, "Out")) || exists(filepath.Join(dir, "Out.partial")) {
			t.Fatal("leftovers")
		}
	}
}

func TestArgon2Ceilings(t *testing.T) {
	v, _ := newTestVault(t)
	orig := make([]byte, headerSize)
	f, err := os.OpenFile(v.Path(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.ReadAt(orig, 0)
	set := func(tm, mem uint32, th uint8) {
		b := append([]byte(nil), orig...)
		binary.BigEndian.PutUint32(b[offTime:], tm)
		binary.BigEndian.PutUint32(b[offMemory:], mem)
		b[offThreads] = th
		f.WriteAt(b, 0)
	}
	bad := []struct {
		tm, mem uint32
		th      uint8
	}{
		{11, 8192, 1}, {0, 8192, 1}, {1, 1<<20 + 1, 1}, {1, 8192, 0}, {1, 8192, 17},
	}
	for _, c := range bad {
		set(c.tm, c.mem, c.th)
		if _, err := Open(v.Path()); !errors.Is(err, ErrBadFormat) {
			t.Errorf("time=%d mem=%d threads=%d: got %v, want ErrBadFormat", c.tm, c.mem, c.th, err)
		}
	}
	set(10, 1<<20, 16)
	if _, err := Open(v.Path()); err != nil {
		t.Errorf("limits themselves rejected: %v", err)
	}
	f.WriteAt(orig, 0)
}

// Extraction hardening beyond TestPathTraversal: none of these may write
// outside dest, and all must fail.
func TestReviewExtractionHardening(t *testing.T) {
	cases := map[string][]tarEnt{
		"file through symlink": {
			{name: "s", typ: tar.TypeSymlink, link: "../victim.txt"},
			{name: "s", typ: tar.TypeReg, body: "pwned"},
		},
		"case-variant parent symlink": {
			{name: "link", typ: tar.TypeSymlink, link: ".."},
			{name: "LINK/victim.txt", typ: tar.TypeReg, body: "pwned"},
		},
		"dir over symlink": {
			{name: "link", typ: tar.TypeSymlink, link: ".."},
			{name: "link/", typ: tar.TypeDir},
			{name: "link/victim.txt", typ: tar.TypeReg, body: "pwned"},
		},
		"dir then file same name": {
			{name: "d/", typ: tar.TypeDir},
			{name: "d", typ: tar.TypeReg, body: "x"},
		},
		"file then dir same name": {
			{name: "d", typ: tar.TypeReg, body: "x"},
			{name: "d/", typ: tar.TypeDir},
		},
		"backslash dotdot": {
			{name: `..\victim.txt`, typ: tar.TypeReg, body: "pwned"},
			{name: "fail/", typ: tar.TypeDir},
			{name: "fail", typ: tar.TypeReg, body: "x"},
		},
		"hardlink then write": {
			{name: "h", typ: tar.TypeLink, link: "../victim.txt"},
			{name: "h", typ: tar.TypeReg, body: "pwned"},
			{name: "h", typ: tar.TypeReg, body: "dup"},
		},
		"marker in archive": {
			{name: sessionFile, typ: tar.TypeSymlink, link: "../victim.txt"},
		},
	}
	for name, ents := range cases {
		t.Run(name, func(t *testing.T) {
			v, dir := newTestVault(t)
			victim := filepath.Join(dir, "x", "victim.txt")
			os.MkdirAll(filepath.Dir(victim), 0o755)
			os.WriteFile(victim, []byte("orig"), 0o644)
			lockRaw(t, v, ents)
			dest := filepath.Join(dir, "x", "Test")
			err := v.Unlock(pw(), dest, nil)
			if err == nil {
				t.Errorf("unlock succeeded")
			}
			if b, _ := os.ReadFile(victim); string(b) != "orig" {
				t.Errorf("victim modified: %q", b)
			}
			if exists(dest) || exists(dest+".partial") {
				t.Errorf("leftovers")
			}
		})
	}
}

// Chunk-level integrity: swapping two chunks, and splicing the data region
// of an earlier lock under the current meta, must both fail.
func TestReviewChunkSwapAndSplice(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "a.bin"), randBytes(t, 300<<10), 0o644)
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(v.Path())
	if err := v.Lock(src, pw(), false, nil); err != nil { // same content, new keys
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(v.Path())

	try := func(name string, img []byte) {
		p := filepath.Join(dir, name+".vault")
		os.WriteFile(p, img, 0o600)
		vv, err := Open(p)
		if err != nil {
			t.Fatal(err)
		}
		err = vv.Unlock(pw(), filepath.Join(dir, name), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: got %v, want ErrCorrupt", name, err)
		}
	}
	swapped := append([]byte(nil), cur...)
	c0 := swapped[headerSize : headerSize+ctChunkSize]
	c1 := swapped[headerSize+ctChunkSize : headerSize+2*ctChunkSize]
	t0 := append([]byte(nil), c0...)
	copy(c0, c1)
	copy(c1, t0)
	try("swapped", swapped)

	spliced := append([]byte(nil), cur[:headerSize]...)
	spliced = append(spliced, old[headerSize:]...)
	try("spliced", spliced)

	mixed := append([]byte(nil), cur...)
	copy(mixed[headerSize+ctChunkSize:headerSize+2*ctChunkSize], old[headerSize+ctChunkSize:])
	try("mixed", mixed)

	// Whole-file rollback (old header + old data) is expected to succeed:
	// there is no external state to detect it.
	p := filepath.Join(dir, "rollback.vault")
	os.WriteFile(p, old, 0o600)
	vv, _ := Open(p)
	if err := vv.Unlock(pw(), filepath.Join(dir, "rollback"), nil); err != nil {
		t.Errorf("rollback: %v", err)
	}
}
