package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLabelFromCreate(t *testing.T) {
	before := time.Now().Unix()
	dir := t.TempDir()
	path := filepath.Join(dir, "L.vault")
	owner := "Zoë Müller 日本"
	if err := Create(path, testCap, owner, pw(), testParams, nil); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l := v.Label()
	if l.Owner != owner {
		t.Fatalf("owner %q, want %q", l.Owner, owner)
	}
	if c := l.Created.Unix(); c < before || c > after {
		t.Fatalf("created %v not in [%d, %d]", l.Created, before, after)
	}
	if !l.LastUnlocked.IsZero() || !l.LastLocked.IsZero() {
		t.Fatalf("new vault has dates %v / %v", l.LastUnlocked, l.LastLocked)
	}
	// Status still works: the label is part of the meta AAD.
	if st, _, err := v.Status(pw()); err != nil || st != StateEmpty {
		t.Fatalf("Status: %v %v", st, err)
	}
}

func TestLabelEmptyOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "E.vault")
	if err := Create(path, testCap, "", pw(), testParams, nil); err != nil {
		t.Fatal(err)
	}
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v.Label().Owner != "" {
		t.Fatalf("owner %q", v.Label().Owner)
	}
	if _, _, err := v.Status(pw()); err != nil {
		t.Fatal(err)
	}
}

func TestLabelBadOwner(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]string{
		"too long":    strings.Repeat("a", ownerSize+1),
		"too long mb": strings.Repeat("é", ownerSize/2) + "a", // 65 bytes
		"newline":     "Ann\nBob",
		"tab":         "Ann\tBob",
		"nul":         "Ann\x00",
		"esc":         "\x1b[31mred",
		"bad utf8":    "Ann\xff",
	}
	for name, owner := range bad {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".vault")
		if err := Create(path, testCap, owner, pw(), testParams, nil); !errors.Is(err, ErrBadLabel) {
			t.Errorf("%s: got %v, want ErrBadLabel", name, err)
		}
		if exists(path) {
			t.Errorf("%s: file created", name)
		}
	}
	path := filepath.Join(dir, "max.vault")
	if err := Create(path, testCap, strings.Repeat("x", ownerSize), pw(), testParams, nil); err != nil {
		t.Fatalf("64-byte owner: %v", err)
	}
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v.Label().Owner != strings.Repeat("x", ownerSize) {
		t.Fatalf("owner %q", v.Label().Owner)
	}
}

func TestLabelDatesOnLockUnlock(t *testing.T) {
	v, dir := newTestVault(t)
	created := v.Label().Created
	src := filepath.Join(dir, "Test")
	writeFile(t, filepath.Join(src, "f.txt"), []byte("hello"), 0o644)

	var prev Label
	for i := 0; i < 2; i++ {
		before := time.Now().Unix()
		if err := v.Lock(src, pw(), true, nil); err != nil {
			t.Fatal(err)
		}
		l := v.Label()
		if l.LastLocked.Unix() < before || l.LastLocked.Before(prev.LastLocked) {
			t.Fatalf("lock %d: lastLocked %v (before=%d, prev=%v)", i, l.LastLocked, before, prev.LastLocked)
		}
		if !l.LastUnlocked.Equal(prev.LastUnlocked) || !l.Created.Equal(created) || l.Owner != "Test Owner" {
			t.Fatalf("lock %d changed other label fields: %+v", i, l)
		}
		// The label on disk matches and authenticates.
		w, err := Open(v.Path())
		if err != nil {
			t.Fatal(err)
		}
		if w.Label() != l {
			t.Fatalf("on-disk label %+v, in-memory %+v", w.Label(), l)
		}
		if _, _, err := w.Status(pw()); err != nil {
			t.Fatalf("Status after lock: %v", err)
		}
		prev = l

		before = time.Now().Unix()
		if err := v.Unlock(pw(), src, nil); err != nil {
			t.Fatal(err)
		}
		l = v.Label()
		if l.LastUnlocked.Unix() < before || l.LastUnlocked.Before(prev.LastUnlocked) {
			t.Fatalf("unlock %d: lastUnlocked %v (before=%d)", i, l.LastUnlocked, before)
		}
		if !l.LastLocked.Equal(prev.LastLocked) || !l.Created.Equal(created) {
			t.Fatalf("unlock %d changed other label fields: %+v", i, l)
		}
		w, err = Open(v.Path())
		if err != nil {
			t.Fatal(err)
		}
		if w.Label() != l {
			t.Fatalf("on-disk label %+v, in-memory %+v", w.Label(), l)
		}
		if _, _, err := w.Status(pw()); err != nil {
			t.Fatalf("Status after unlock: %v", err)
		}
		prev = l
	}
}

func TestLabelTamperDetected(t *testing.T) {
	cases := map[string]struct {
		off  int64
		flip byte
	}{
		"owner":        {offOwner, 0x01},         // 'T' -> 'U': still valid text
		"owner pad":    {offOwner + 20, 0x41},    // padding after the name: rejected by Open
		"created":      {offCreated + 7, 0x01},   // one second off
		"lastUnlocked": {offLastUnlocked + 7, 1}, // "never" -> 1970
		"lastLocked":   {offLastLocked + 7, 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v, _ := newTestVault(t)
			f, err := os.OpenFile(v.Path(), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 1)
			f.ReadAt(b, c.off)
			b[0] ^= c.flip
			f.WriteAt(b, c.off)
			f.Close()

			w, err := Open(v.Path())
			if name == "owner pad" {
				// A non-zero byte after the terminating zero is malformed.
				if !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrBadLabel) {
					t.Fatalf("Open: %v, want ErrCorrupt/ErrBadLabel", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if _, _, err := w.Status(pw()); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("Status: %v, want ErrWrongPassword", err)
			}
		})
	}
}

func TestLabelMalformedRejectedByOpen(t *testing.T) {
	v, _ := newTestVault(t)
	f, err := os.OpenFile(v.Path(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	orig := make([]byte, 1)
	f.ReadAt(orig, offOwner+1)
	for _, c := range []byte{0x07, 0x1f, 0xff} {
		f.WriteAt([]byte{c}, offOwner+1)
		if _, err := Open(v.Path()); !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrBadLabel) {
			t.Errorf("owner byte %#x: Open %v, want ErrCorrupt/ErrBadLabel", c, err)
		}
	}
	f.WriteAt(orig, offOwner+1)
	f.WriteAt([]byte{0x80}, offCreated) // date > MaxInt64
	if _, err := Open(v.Path()); !errors.Is(err, ErrBadLabel) {
		t.Errorf("huge date: Open %v, want ErrBadLabel", err)
	}
}
