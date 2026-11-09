package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	headerSize    = 4096
	magic         = "EFVAULT1"
	formatVersion = 3 // 1 was never released; 2 had no label block

	saltSize      = 32
	nonceSize     = 12
	lockSaltSize  = 16
	tokenSize     = 16
	keySize       = 32
	tagSize       = 16
	metaPlainSize = 1 + 8 + lockSaltSize + tokenSize // 41
	metaCTSize    = metaPlainSize + tagSize          // 57

	offVersion  = 8
	offTime     = 10
	offMemory   = 14
	offThreads  = 18
	offSalt     = 19
	offCapacity = 51
	offNonce    = 59
	offMetaCT   = 71
	offEnd      = offMetaCT + metaCTSize // 128: end of the meta ciphertext

	// Label block: plaintext, authenticated as part of the meta AAD.
	ownerSize       = 64
	offLabel        = offEnd               // 128
	offOwner        = offLabel             // 128
	offCreated      = offOwner + ownerSize // 192
	offLastUnlocked = offCreated + 8       // 200
	offLastLocked   = offLastUnlocked + 8  // 208
	offLabelEnd     = offLastLocked + 8    // 216

	minCapacity = 1 << 20

	// Upper bounds on Argon2 parameters read from a header. The header is
	// unauthenticated until after key derivation, so without these a
	// crafted file could make Open/Status allocate absurd amounts of memory.
	maxTime      = 10
	maxMemoryKiB = 1 << 20 // 1 GiB
	maxThreads   = 16

	infoMeta = "vaultlock/meta/v1"
	infoData = "vaultlock/data/v1"
)

// header is the parsed form of the first 4096 bytes of a vault.
type header struct {
	params   Params
	salt     [saltSize]byte
	capacity int64
	nonce    [nonceSize]byte
	metaCT   [metaCTSize]byte
	label    label
}

// label is the plaintext label block. It is authenticated only through the
// meta AAD, so it is trusted for display and nothing else.
type label struct {
	owner        [ownerSize]byte // UTF-8, zero-padded
	created      int64           // unix seconds
	lastUnlocked int64           // unix seconds, 0 = never
	lastLocked   int64           // unix seconds, 0 = never
}

// meta is the decrypted meta block.
type meta struct {
	state    State
	usedLen  int64
	lockSalt [lockSaltSize]byte
	// sessionToken identifies the folder produced by the latest Unlock (or
	// kept by the latest Lock); a copy is stored in sessionFile there.
	sessionToken [tokenSize]byte
}

func (h *header) marshal() []byte {
	b := make([]byte, headerSize)
	copy(b, magic)
	binary.BigEndian.PutUint16(b[offVersion:], formatVersion)
	binary.BigEndian.PutUint32(b[offTime:], h.params.Time)
	binary.BigEndian.PutUint32(b[offMemory:], h.params.MemoryKiB)
	b[offThreads] = h.params.Threads
	copy(b[offSalt:], h.salt[:])
	binary.BigEndian.PutUint64(b[offCapacity:], uint64(h.capacity))
	copy(b[offNonce:], h.nonce[:])
	copy(b[offMetaCT:], h.metaCT[:])
	copy(b[offOwner:], h.label.owner[:])
	binary.BigEndian.PutUint64(b[offCreated:], uint64(h.label.created))
	binary.BigEndian.PutUint64(b[offLastUnlocked:], uint64(h.label.lastUnlocked))
	binary.BigEndian.PutUint64(b[offLastLocked:], uint64(h.label.lastLocked))
	return b
}

// metaAAD returns header bytes 0..59 followed by the label block (bytes
// 128..216), the additional data of the meta block.
func (h *header) metaAAD() []byte {
	b := h.marshal()
	aad := make([]byte, 0, offNonce+offLabelEnd-offLabel)
	aad = append(aad, b[:offNonce]...)
	return append(aad, b[offLabel:offLabelEnd]...)
}

// validOwner reports whether owner fits the label block: at most ownerSize
// bytes of valid UTF-8 with no bytes below 0x20.
func validOwner(owner []byte) bool {
	if len(owner) > ownerSize || !utf8.Valid(owner) {
		return false
	}
	for _, c := range owner {
		if c < 0x20 {
			return false
		}
	}
	return true
}

// parseLabel decodes and validates the label block b[offLabel:offLabelEnd].
func parseLabel(b []byte) (label, error) {
	var l label
	raw := b[offOwner : offOwner+ownerSize]
	n := bytes.IndexByte(raw, 0)
	if n < 0 {
		n = ownerSize
	}
	if !validOwner(raw[:n]) || !allZero(raw[n:]) {
		return label{}, fmt.Errorf("%w: %w: invalid owner name", ErrCorrupt, ErrBadLabel)
	}
	copy(l.owner[:], raw)
	ts := [3]*int64{&l.created, &l.lastUnlocked, &l.lastLocked}
	for i, off := range [3]int{offCreated, offLastUnlocked, offLastLocked} {
		v := binary.BigEndian.Uint64(b[off:])
		if v > math.MaxInt64 {
			return label{}, fmt.Errorf("%w: %w: invalid date", ErrCorrupt, ErrBadLabel)
		}
		*ts[i] = int64(v)
	}
	return l, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func parseHeader(b []byte) (*header, error) {
	if len(b) < headerSize || string(b[:len(magic)]) != magic {
		return nil, ErrBadFormat
	}
	if v := binary.BigEndian.Uint16(b[offVersion:]); v != formatVersion {
		return nil, fmt.Errorf("%w: unsupported format version %d", ErrBadFormat, v)
	}
	h := &header{}
	h.params.Time = binary.BigEndian.Uint32(b[offTime:])
	h.params.MemoryKiB = binary.BigEndian.Uint32(b[offMemory:])
	h.params.Threads = b[offThreads]
	if err := validateParams(h.params); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadFormat, err)
	}
	c := binary.BigEndian.Uint64(b[offCapacity:])
	if c < minCapacity || c > math.MaxInt64 {
		return nil, fmt.Errorf("%w: invalid capacity", ErrBadFormat)
	}
	h.capacity = int64(c)
	copy(h.salt[:], b[offSalt:])
	copy(h.nonce[:], b[offNonce:])
	copy(h.metaCT[:], b[offMetaCT:])
	l, err := parseLabel(b)
	if err != nil {
		return nil, err
	}
	h.label = l
	return h, nil
}

func validateParams(p Params) error {
	if p.Time < 1 || p.Time > maxTime {
		return fmt.Errorf("vault: argon2 time %d out of range 1..%d", p.Time, maxTime)
	}
	if p.Threads < 1 || p.Threads > maxThreads {
		return fmt.Errorf("vault: argon2 threads %d out of range 1..%d", p.Threads, maxThreads)
	}
	if p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxMemoryKiB {
		return fmt.Errorf("vault: argon2 memory %d KiB out of range", p.MemoryKiB)
	}
	return nil
}

// readHeader reads and parses the header of f and checks that the file size
// matches the recorded capacity.
func readHeader(f *os.File) (*header, error) {
	b := make([]byte, headerSize)
	if _, err := f.ReadAt(b, 0); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrBadFormat
		}
		return nil, err
	}
	h, err := parseHeader(b)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() != h.capacity {
		return nil, fmt.Errorf("%w: file size %d does not match capacity %d", ErrCorrupt, fi.Size(), h.capacity)
	}
	return h, nil
}

// writeMeta writes the meta nonce, the meta ciphertext and the label block
// (header bytes 59..216) in one write, so the label and the meta sealed over
// it reach the disk together.
func writeMeta(f io.WriterAt, h *header) error {
	_, err := f.WriteAt(h.marshal()[offNonce:offLabelEnd], offNonce)
	return err
}

// keys holds the password-derived master key and K_meta.
type keys struct{ master, meta []byte }

// deriveKeys runs Argon2id and HKDF. It zeroes password.
func deriveKeys(password []byte, h *header) (*keys, error) {
	master := argon2.IDKey(password, h.salt[:], h.params.Time, h.params.MemoryKiB, h.params.Threads, keySize)
	wipe(password)
	km, err := deriveSubKey(master, h.salt[:], infoMeta)
	if err != nil {
		wipe(master)
		return nil, err
	}
	return &keys{master: master, meta: km}, nil
}

func (k *keys) wipe() {
	wipe(k.master)
	wipe(k.meta)
}

func deriveSubKey(master, salt []byte, info string) ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, salt, []byte(info)), k); err != nil {
		return nil, err
	}
	return k, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// openMeta authenticates and decodes the meta block.
func (h *header) openMeta(kMeta []byte) (meta, error) {
	aead, err := newAEAD(kMeta)
	if err != nil {
		return meta{}, err
	}
	pt, err := aead.Open(nil, h.nonce[:], h.metaCT[:], h.metaAAD())
	if err != nil {
		return meta{}, ErrWrongPassword
	}
	defer wipe(pt)
	var m meta
	m.state = State(pt[0])
	used := binary.BigEndian.Uint64(pt[1:9])
	copy(m.lockSalt[:], pt[9:9+lockSaltSize])
	copy(m.sessionToken[:], pt[9+lockSaltSize:])
	switch m.state {
	case StateEmpty:
		if used != 0 {
			return meta{}, fmt.Errorf("%w: empty vault with non-zero length", ErrCorrupt)
		}
	case StateLocked:
		if used < tagSize || used > uint64(h.capacity-headerSize) {
			return meta{}, fmt.Errorf("%w: invalid stream length", ErrCorrupt)
		}
	default:
		return meta{}, fmt.Errorf("%w: unknown state %d", ErrCorrupt, m.state)
	}
	m.usedLen = int64(used)
	return m, nil
}

// sealMeta encrypts m under kMeta with the given nonce and stores both in h.
// The AAD covers h's current label, so set the label before sealing.
// The caller must pass a nonce that has never been used with kMeta (in
// practice: 12 fresh bytes from crypto/rand).
func (h *header) sealMeta(kMeta []byte, nonce [nonceSize]byte, m meta) error {
	aead, err := newAEAD(kMeta)
	if err != nil {
		return err
	}
	h.nonce = nonce
	pt := make([]byte, metaPlainSize)
	defer wipe(pt)
	pt[0] = byte(m.state)
	binary.BigEndian.PutUint64(pt[1:9], uint64(m.usedLen))
	copy(pt[9:], m.lockSalt[:])
	copy(pt[9+lockSaltSize:], m.sessionToken[:])
	ct := aead.Seal(nil, h.nonce[:], pt, h.metaAAD())
	copy(h.metaCT[:], ct)
	return nil
}

func randRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}

func randomNonce() ([nonceSize]byte, error) {
	var n [nonceSize]byte
	err := randRead(n[:])
	return n, err
}

// wipe zeroes b (best effort; see package documentation).
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
