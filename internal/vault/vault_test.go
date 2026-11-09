package vault

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testParams = Params{Time: 1, MemoryKiB: 8192, Threads: 1}

const testCap = 2 << 20

func pw() []byte      { return []byte("correct horse battery staple") }
func wrongPW() []byte { return []byte("correct horse battery stapl3") }

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Test.vault")
	if err := Create(path, testCap, "Test Owner", pw(), testParams, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	v, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v, dir
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, data []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// readMeta decrypts the on-disk meta block.
func readMeta(t *testing.T, path string) (*header, meta) {
	t.Helper()
	f, err := os.Open(path)
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
	return h, m
}

// rewriteMeta re-seals the meta block after applying change.
func rewriteMeta(t *testing.T, path string, change func(*meta)) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
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
	change(&m)
	nonce, err := randomNonce()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sealMeta(ks.meta, nonce, m); err != nil {
		t.Fatal(err)
	}
	if err := writeMeta(f, h); err != nil {
		t.Fatal(err)
	}
}

type entry struct {
	typ   fs.FileMode
	perm  fs.FileMode
	mtime int64
	hash  [32]byte
	link  string
}

func snapshot(t *testing.T, root string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if rel == sessionFile {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := entry{typ: info.Mode().Type(), perm: info.Mode().Perm()}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			e.link, err = os.Readlink(p)
			if err != nil {
				return err
			}
			e.perm = 0 // symlink modes/mtimes are not restored
		case info.Mode().IsRegular():
			e.hash = fileHash(t, p)
			e.mtime = info.ModTime().Unix()
		default:
			e.mtime = info.ModTime().Unix()
		}
		out[filepath.ToSlash(rel)] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// buildTree creates a folder exercising nested dirs, empty files, a
// multi-chunk file, symlinks, unicode names and assorted modes and mtimes.
func buildTree(t *testing.T, root string) {
	t.Helper()
	big := randBytes(t, 3*chunkSize+777)
	writeFile(t, filepath.Join(root, "big.bin"), big, 0o644)
	writeFile(t, filepath.Join(root, "empty.txt"), nil, 0o600)
	writeFile(t, filepath.Join(root, "a", "b", "c", "deep.txt"), []byte("deep"), 0o640)
	writeFile(t, filepath.Join(root, "a", "b", "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755)
	writeFile(t, filepath.Join(root, "ünïcødé", "日本語 ファイル.txt"), []byte("こんにちは"), 0o644)
	writeFile(t, filepath.Join(root, "emoji 🎉.txt"), []byte("party"), 0o644)
	if err := os.MkdirAll(filepath.Join(root, "empty-dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "empty-dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a/b/c/deep.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/outside/target", filepath.Join(root, "abs-link")); err != nil {
		t.Fatal(err)
	}
	// Distinct second-precision mtimes; directories last so creating
	// children does not change them.
	ts := time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)
	var files, dirs []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if p == root || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		} else {
			files = append(files, p)
		}
		return nil
	})
	for i, p := range append(files, dirs...) {
		mt := ts.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHeaderLayout(t *testing.T) {
	if offEnd != 128 || metaPlainSize != 41 || metaCTSize != 57 || offEnd > headerSize {
		t.Fatalf("layout constants wrong: offEnd=%d", offEnd)
	}
	if offLabel != 128 || offOwner != 128 || ownerSize != 64 || offCreated != 192 ||
		offLastUnlocked != 200 || offLastLocked != 208 || offLabelEnd != 216 || offLabelEnd > headerSize {
		t.Fatalf("label layout constants wrong: offLabelEnd=%d", offLabelEnd)
	}
	if formatVersion != 3 {
		t.Fatalf("formatVersion = %d, want 3", formatVersion)
	}
	h := &header{}
	copy(h.label.owner[:], "Ann")
	h.label.created = 0x0102030405060708
	b := h.marshal()
	if string(b[offOwner:offOwner+3]) != "Ann" || b[offOwner+3] != 0 || b[offCreated] != 1 || b[offCreated+7] != 8 {
		t.Fatalf("label bytes %x", b[offLabel:offLabelEnd])
	}
	aad := h.metaAAD()
	if len(aad) != offNonce+offLabelEnd-offLabel || !bytes.Equal(aad[:offNonce], b[:offNonce]) || !bytes.Equal(aad[offNonce:], b[offLabel:offLabelEnd]) {
		t.Fatal("metaAAD is not header[0:59] || header[128:216]")
	}
	n := chunkNonce(0x0102030405060708, true)
	want := [12]byte{0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1}
	if n != want {
		t.Fatalf("nonce = %x, want %x", n, want)
	}
}

func TestCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.vault")
	var last [2]int64
	calls := 0
	if err := Create(path, testCap, "Test Owner", pw(), testParams, func(d, tot int64) {
		if d < last[0] {
			t.Errorf("progress went backwards")
		}
		last = [2]int64{d, tot}
		calls++
	}); err != nil {
		t.Fatal(err)
	}
	if calls < 2 || last[0] != last[1] || last[1] != testCap-headerSize {
		t.Errorf("progress: calls=%d last=%v", calls, last)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != testCap {
		t.Fatalf("size %d, want %d", fi.Size(), testCap)
	}
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v.Capacity() != testCap || v.Path() != path {
		t.Fatal("Capacity/Path mismatch")
	}
	p := pw()
	st, used, err := v.Status(p)
	if err != nil || st != StateEmpty || used != 0 {
		t.Fatalf("Status = %v %v %v", st, used, err)
	}
	if !bytes.Equal(p, make([]byte, len(p))) {
		t.Error("password slice was not zeroed")
	}

	// Never overwrite an existing path.
	before := fileHash(t, path)
	if err := Create(path, testCap, "Test Owner", pw(), testParams, nil); err == nil {
		t.Fatal("Create over existing file succeeded")
	}
	if fileHash(t, path) != before {
		t.Fatal("existing file modified")
	}
	// Minimum capacity.
	small := filepath.Join(dir, "small.vault")
	if err := Create(small, minCapacity-1, "Test Owner", pw(), testParams, nil); err == nil {
		t.Fatal("Create below 1 MiB succeeded")
	}
	if exists(small) {
		t.Fatal("file left behind")
	}
	if err := Create(filepath.Join(dir, "min.vault"), minCapacity, "", pw(), testParams, nil); err != nil {
		t.Fatalf("Create at exactly 1 MiB: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	buildTree(t, src)
	want := snapshot(t, src)

	var lockProg [][2]int64
	if err := v.Lock(src, pw(), true, func(d, tot int64) { lockProg = append(lockProg, [2]int64{d, tot}) }); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if exists(src) {
		t.Fatal("source folder not removed")
	}
	for i := 1; i < len(lockProg); i++ {
		if lockProg[i][0] < lockProg[i-1][0] || lockProg[i][1] != lockProg[0][1] {
			t.Fatalf("lock progress not monotonic: %v", lockProg)
		}
	}
	if l := lockProg[len(lockProg)-1]; l[0] != l[1] {
		t.Fatalf("lock progress did not finish: %v", l)
	}
	st, used, err := v.Status(pw())
	if err != nil || st != StateLocked || used <= 0 {
		t.Fatalf("Status = %v %v %v", st, used, err)
	}

	var last [2]int64
	if err := v.Unlock(pw(), src, func(d, tot int64) { last = [2]int64{d, tot} }); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if last[0] != used || last[1] != used {
		t.Errorf("unlock progress final = %v, used %d", last, used)
	}
	got := snapshot(t, src)
	if len(got) != len(want) {
		t.Errorf("entry count %d, want %d", len(got), len(want))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("missing %q", name)
			continue
		}
		if g != w {
			t.Errorf("%q: got %+v, want %+v", name, g, w)
		}
	}
	if exists(src + ".partial") {
		t.Error("partial directory left behind")
	}
	// Unlock leaves the vault content in place.
	if st, _, _ := v.Status(pw()); st != StateLocked {
		t.Error("vault no longer locked after Unlock")
	}
}

func TestEmptyFolderRoundTrip(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	os.Mkdir(src, 0o755)
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(pw(), src, nil); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(src)
	if len(ents) != 1 || ents[0].Name() != sessionFile {
		t.Fatalf("expected an empty folder with only the session marker, got %v", ents)
	}
}

func TestWrongPassword(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "f.txt"), []byte("hello"), 0o644)
	if _, _, err := v.Status(wrongPW()); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Status: %v", err)
	}
	before := fileHash(t, v.Path())
	if err := v.Lock(src, wrongPW(), true, nil); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Lock: %v", err)
	}
	if fileHash(t, v.Path()) != before || !exists(src) {
		t.Fatal("Lock with wrong password modified the vault or the folder")
	}
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(wrongPW(), src, nil); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unlock: %v", err)
	}
	if exists(src) || exists(src+".partial") {
		t.Fatal("folder created on wrong password")
	}
}

func TestUnlockEmpty(t *testing.T) {
	v, dir := newTestVault(t)
	dest := filepath.Join(dir, "Test")
	if err := v.Unlock(pw(), dest, nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("got %v, want ErrEmpty", err)
	}
	if exists(dest) || exists(dest+".partial") {
		t.Fatal("folder created for empty vault")
	}
}

func TestTooLarge(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "small.txt"), []byte("small"), 0o644)
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "huge.bin"), make([]byte, testCap), 0o644)
	before := fileHash(t, v.Path())
	if err := v.Lock(src, pw(), true, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if fileHash(t, v.Path()) != before {
		t.Fatal("vault modified by a rejected Lock")
	}
	if !exists(filepath.Join(src, "huge.bin")) {
		t.Fatal("source removed")
	}
	// The previous content is still intact.
	dest := filepath.Join(dir, "Out")
	if err := v.Unlock(pw(), dest, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "small.txt")); string(b) != "small" {
		t.Fatal("old content lost")
	}
}

func TestTooLargeMidStream(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "f.txt"), []byte("x"), 0o644)
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	// Estimate passes, but the stream turns out larger than the vault.
	err := v.lockStream(pw(), lockJob{est: 100, produce: func(w io.Writer) error {
		_, err := io.Copy(w, io.LimitReader(zeroReader{}, testCap))
		return err
	}}, nil)
	if !errors.Is(err, ErrTooLarge) || !errors.Is(err, ErrVaultEmptied) {
		t.Fatalf("got %v, want ErrTooLarge and ErrVaultEmptied", err)
	}
	var ee *EmptiedError
	if !errors.As(err, &ee) || errors.Unwrap(err) != ErrTooLarge {
		t.Fatalf("got %#v, want *EmptiedError wrapping ErrTooLarge", err)
	}
	st, used, err := v.Status(pw())
	if err != nil || st != StateEmpty || used != 0 {
		t.Fatalf("after overflow: %v %v %v (want empty)", st, used, err)
	}
	if fi, _ := os.Stat(v.Path()); fi.Size() != testCap {
		t.Fatal("file size changed")
	}
	if !exists(filepath.Join(src, "f.txt")) {
		t.Fatal("source touched")
	}
}

// lockBytes stores raw as the plaintext stream without any entry check.
func lockBytes(v *Vault, raw []byte) error {
	return v.lockStream(pw(), lockJob{est: streamSize(int64(len(raw))), produce: func(w io.Writer) error {
		_, err := w.Write(raw)
		return err
	}}, nil)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func lockedTestVault(t *testing.T) (*Vault, string, int64) {
	t.Helper()
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	buildTree(t, src)
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	_, used, err := v.Status(pw())
	if err != nil {
		t.Fatal(err)
	}
	return v, dir, used
}

func flipByte(t *testing.T, path string, off int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptCiphertext(t *testing.T) {
	cases := map[string]func(used int64) int64{
		"first chunk": func(int64) int64 { return headerSize + 10 },
		"third chunk": func(int64) int64 { return headerSize + 2*ctChunkSize + 10 },
		"final tag":   func(used int64) int64 { return headerSize + used - 1 },
	}
	for name, off := range cases {
		t.Run(name, func(t *testing.T) {
			v, dir, used := lockedTestVault(t)
			flipByte(t, v.Path(), off(used))
			dest := filepath.Join(dir, "Test")
			if err := v.Unlock(pw(), dest, nil); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			if exists(dest) || exists(dest+".partial") {
				t.Fatal("partial output left behind")
			}
		})
	}
	t.Run("header salt", func(t *testing.T) {
		v, dir, _ := lockedTestVault(t)
		flipByte(t, v.Path(), offSalt+3)
		if err := v.Unlock(pw(), filepath.Join(dir, "Test"), nil); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("got %v, want ErrWrongPassword", err)
		}
	})
}

func TestTruncation(t *testing.T) {
	cases := map[string]func(used int64) int64{
		"longer":           func(u int64) int64 { return u + 100 },
		"shorter":          func(u int64) int64 { return u - 1 },
		"first chunk only": func(int64) int64 { return ctChunkSize },
		"past capacity":    func(int64) int64 { return testCap },
	}
	for name, newUsed := range cases {
		t.Run(name, func(t *testing.T) {
			v, dir, used := lockedTestVault(t)
			rewriteMeta(t, v.Path(), func(m *meta) { m.usedLen = newUsed(used) })
			dest := filepath.Join(dir, "Test")
			if err := v.Unlock(pw(), dest, nil); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			if exists(dest) || exists(dest+".partial") {
				t.Fatal("partial output left behind")
			}
		})
	}
}

func TestOpenBadFormat(t *testing.T) {
	dir := t.TempDir()
	rnd := filepath.Join(dir, "random.vault")
	writeFile(t, rnd, randBytes(t, testCap), 0o600)
	if _, err := Open(rnd); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("random file: %v", err)
	}
	short := filepath.Join(dir, "short.vault")
	writeFile(t, short, []byte(magic), 0o600)
	if _, err := Open(short); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("short file: %v", err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open on a directory succeeded")
	}
	// Absurd Argon2 memory in the (not yet authenticated) header.
	v, _ := newTestVault(t)
	f, _ := os.OpenFile(v.Path(), os.O_RDWR, 0)
	f.WriteAt([]byte{0xff, 0xff, 0xff, 0xff}, offMemory)
	f.Close()
	if _, err := Open(v.Path()); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("huge memory param: %v", err)
	}
}

func TestLockTwice(t *testing.T) {
	v, dir := newTestVault(t)
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "big.bin"), randBytes(t, 600<<10), 0o644)
	if err := v.Lock(src, pw(), false, nil); err != nil {
		t.Fatal(err)
	}
	s1, _ := os.ReadFile(v.Path())
	h1, m1 := readMeta(t, v.Path())

	removeTree(src)
	small := randBytes(t, 10<<10)
	writeFile(t, filepath.Join(src, "small.bin"), small, 0o644)
	if err := v.Lock(src, pw(), true, nil); err != nil {
		t.Fatal(err)
	}
	s2, _ := os.ReadFile(v.Path())
	h2, m2 := readMeta(t, v.Path())

	if h1.nonce == h2.nonce {
		t.Error("meta nonce reused")
	}
	if m1.lockSalt == m2.lockSalt {
		t.Error("lockSalt reused")
	}
	if !(m2.usedLen < m1.usedLen) {
		t.Fatalf("usedLen %d !< %d", m2.usedLen, m1.usedLen)
	}
	lo, hi := headerSize+m2.usedLen, headerSize+m1.usedLen
	same := 0
	for i := lo; i < hi; i++ {
		if s1[i] == s2[i] {
			same++
		}
	}
	if n := hi - lo; int64(same) > n/32 {
		t.Errorf("old ciphertext tail not overwritten: %d of %d bytes unchanged", same, n)
	}
	if !bytes.Equal(s1[hi:], s2[hi:]) {
		t.Error("filler beyond the old stream changed")
	}
	if bytes.Equal(s1[headerSize:lo], s2[headerSize:lo]) {
		t.Error("new stream identical to old")
	}
	if err := v.Unlock(pw(), src, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, "small.bin")); !bytes.Equal(b, small) {
		t.Fatal("content mismatch after second lock")
	}
	if exists(filepath.Join(src, "big.bin")) {
		t.Fatal("old content resurfaced")
	}
}

func TestDestExists(t *testing.T) {
	v, dir, _ := lockedTestVault(t)
	dest := filepath.Join(dir, "Test")
	os.Mkdir(dest, 0o755)
	if err := v.Unlock(pw(), dest, nil); !errors.Is(err, ErrFolderExists) {
		t.Fatalf("dir: %v", err)
	}
	os.Remove(dest)
	writeFile(t, dest, []byte("x"), 0o644)
	if err := v.Unlock(pw(), dest, nil); !errors.Is(err, ErrFolderExists) {
		t.Fatalf("file: %v", err)
	}
}

type tarEnt struct {
	name, link string
	typ        byte
	body       string
}

func TestPathTraversal(t *testing.T) {
	cases := map[string][]tarEnt{
		"dotdot":        {{name: "ok.txt", typ: tar.TypeReg, body: "fine"}, {name: "../evil.txt", typ: tar.TypeReg, body: "pwned"}},
		"nested dotdot": {{name: "a/", typ: tar.TypeDir}, {name: "a/../../evil.txt", typ: tar.TypeReg, body: "pwned"}},
		"absolute":      {{name: "ABS", typ: tar.TypeReg, body: "pwned"}},
		"symlink escape": {
			{name: "d/", typ: tar.TypeDir},
			{name: "d/s", typ: tar.TypeSymlink, link: "../.."},
			{name: "d/s/evil.txt", typ: tar.TypeReg, body: "pwned"},
		},
		"dotdot symlink": {{name: "../evil.txt", typ: tar.TypeSymlink, link: "/etc/passwd"}},
	}
	for name, ents := range cases {
		t.Run(name, func(t *testing.T) {
			v, dir := newTestVault(t)
			absEvil := filepath.Join(dir, "abs-evil.txt")
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			for _, e := range ents {
				n := e.name
				if n == "ABS" {
					n = filepath.ToSlash(absEvil)
				}
				h := &tar.Header{Name: n, Typeflag: e.typ, Linkname: e.link, Mode: 0o644, Size: int64(len(e.body)), Format: tar.FormatPAX}
				if e.typ != tar.TypeReg {
					h.Size = 0
				}
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				io.WriteString(tw, e.body)
			}
			tw.Close()
			raw := buf.Bytes()
			if err := lockBytes(v, raw); err != nil {
				t.Fatalf("lockStream: %v", err)
			}
			// dest is two levels down so "../.." stays inside the temp dir.
			dest := filepath.Join(dir, "x", "Test")
			os.Mkdir(filepath.Join(dir, "x"), 0o755)
			err := v.Unlock(pw(), dest, nil)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			for _, p := range []string{
				dest, dest + ".partial", absEvil,
				filepath.Join(dir, "x", "evil.txt"),
				filepath.Join(dir, "evil.txt"),
			} {
				if exists(p) {
					t.Errorf("%s exists after rejected unlock", p)
				}
			}
		})
	}
}

func TestDestroy(t *testing.T) {
	v, dir := newTestVault(t)
	alias := filepath.Join(dir, "alias")
	if err := os.Link(v.Path(), alias); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	orig := make([]byte, headerSize)
	f, _ := os.Open(alias)
	f.ReadAt(orig, 0)
	f.Close()
	if err := Destroy(v.Path()); err != nil {
		t.Fatal(err)
	}
	if exists(v.Path()) {
		t.Fatal("file not removed")
	}
	now, _ := os.ReadFile(alias)
	if bytes.Equal(now[:headerSize], orig) {
		t.Fatal("header not overwritten")
	}
	if _, err := Open(alias); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("Open after Destroy: %v", err)
	}
}

func TestLockRejectsVaultInsideFolder(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Test")
	os.Mkdir(src, 0o755)
	path := filepath.Join(src, "inner.vault")
	if err := Create(path, testCap, "Test Owner", pw(), testParams, nil); err != nil {
		t.Fatal(err)
	}
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(src, pw(), true, nil); err == nil {
		t.Fatal("Lock of a folder containing the vault succeeded")
	}
}
