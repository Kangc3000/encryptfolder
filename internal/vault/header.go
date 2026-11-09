package vault

import (
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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	headerSize    = 4096
	magic         = "EFVAULT1"
	formatVersion = 2 // 1 was never released; it bound chunks to the meta nonce and had no session token

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
	offEnd      = offMetaCT + metaCTSize // 128

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
	return b
}

// metaAAD returns header bytes 0..59, the additional data of the meta block.
func (h *header) metaAAD() []byte { return h.marshal()[:offNonce] }

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

// writeMeta writes the meta nonce and ciphertext (header bytes 59..128).
func writeMeta(f io.WriterAt, h *header) error {
	_, err := f.WriteAt(h.marshal()[offNonce:offEnd], offNonce)
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
