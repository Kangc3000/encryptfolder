package vault

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	chunkSize   = 64 << 10
	ctChunkSize = chunkSize + tagSize
)

// streamSize returns the ciphertext length of a plain-byte stream as
// produced by chunkWriter: ceil(plain/64KiB) chunks (at least one), each
// with a 16-byte tag.
func streamSize(plain int64) int64 {
	chunks := (plain + chunkSize - 1) / chunkSize
	if chunks == 0 {
		chunks = 1
	}
	return plain + chunks*tagSize
}

// chunkNonce builds the 12-byte nonce: 3 zero bytes || 8-byte big-endian
// chunk counter || 1-byte flag (0x00 more chunks follow, 0x01 final).
func chunkNonce(counter uint64, final bool) [nonceSize]byte {
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[3:11], counter)
	if final {
		n[11] = 1
	}
	return n
}

// chunkWriter encrypts everything written to it into 64 KiB GCM chunks and
// writes them sequentially with WriteAt starting at start. It never writes
// at or beyond limit; a chunk that would do so fails with ErrTooLarge.
// Close emits the final chunk.
type chunkWriter struct {
	dst     io.WriterAt
	aead    cipher.AEAD
	aad     []byte
	start   int64
	off     int64
	limit   int64
	counter uint64
	buf     []byte
	ct      []byte
	touched bool // a WriteAt has been attempted
	closed  bool
	err     error
	prog    func(written int64)
}

func newChunkWriter(dst io.WriterAt, aead cipher.AEAD, aad []byte, start, limit int64, prog func(int64)) *chunkWriter {
	return &chunkWriter{
		dst:   dst,
		aead:  aead,
		aad:   append([]byte(nil), aad...),
		start: start,
		off:   start,
		limit: limit,
		buf:   make([]byte, 0, chunkSize),
		ct:    make([]byte, 0, ctChunkSize),
		prog:  prog,
	}
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("vault: write after close")
	}
	n := 0
	for len(p) > 0 {
		// A full buffer is flushed as a non-final chunk only once more data
		// arrives, so the last chunk is always emitted by Close as final.
		if len(w.buf) == chunkSize {
			if err := w.flush(false); err != nil {
				w.err = err
				return n, err
			}
		}
		k := copy(w.buf[len(w.buf):chunkSize], p)
		w.buf = w.buf[:len(w.buf)+k]
		p = p[k:]
		n += k
	}
	return n, nil
}

func (w *chunkWriter) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	w.closed = true
	err := w.flush(true)
	w.wipeBuffers()
	if err != nil {
		w.err = err
	}
	return err
}

func (w *chunkWriter) flush(final bool) error {
	nonce := chunkNonce(w.counter, final)
	ct := w.aead.Seal(w.ct[:0], nonce[:], w.buf, w.aad)
	if int64(len(ct)) > w.limit-w.off {
		return ErrTooLarge
	}
	w.touched = true
	if _, err := w.dst.WriteAt(ct, w.off); err != nil {
		return err
	}
	w.off += int64(len(ct))
	w.counter++
	w.buf = w.buf[:0]
	if w.prog != nil {
		w.prog(w.off - w.start)
	}
	return nil
}

// wipeBuffers zeroes the plaintext buffer (best effort). It is safe to call
// on every path, including after an error.
func (w *chunkWriter) wipeBuffers() {
	wipe(w.buf[:cap(w.buf)])
	w.buf = w.buf[:0]
}

// written returns the number of ciphertext bytes written so far.
func (w *chunkWriter) written() int64 { return w.off - w.start }

// chunkReader decrypts a stream written by chunkWriter. The chunk that ends
// exactly at used must carry the final flag; all earlier chunks must not.
// Any authentication failure is reported as ErrCorrupt and is sticky.
type chunkReader struct {
	src     io.ReaderAt
	aead    cipher.AEAD
	aad     []byte
	base    int64
	used    int64
	pos     int64
	counter uint64
	ct      []byte
	plain   []byte
	pending []byte
	done    bool
	err     error
	prog    func(read int64)
}

func newChunkReader(src io.ReaderAt, aead cipher.AEAD, aad []byte, base, used int64, prog func(int64)) *chunkReader {
	return &chunkReader{
		src:   src,
		aead:  aead,
		aad:   append([]byte(nil), aad...),
		base:  base,
		used:  used,
		ct:    make([]byte, ctChunkSize),
		plain: make([]byte, 0, chunkSize),
		prog:  prog,
	}
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			r.err = err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *chunkReader) next() error {
	remaining := r.used - r.pos
	if remaining <= 0 {
		return fmt.Errorf("%w: stream ends without a final chunk", ErrCorrupt)
	}
	n := int64(ctChunkSize)
	final := false
	if remaining <= ctChunkSize {
		n = remaining
		final = true
	}
	if n < tagSize {
		return fmt.Errorf("%w: short chunk", ErrCorrupt)
	}
	ct := r.ct[:n]
	if _, err := r.src.ReadAt(ct, r.base+r.pos); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: vault file is truncated", ErrCorrupt)
		}
		return err
	}
	nonce := chunkNonce(r.counter, final)
	pt, err := r.aead.Open(r.plain[:0], nonce[:], ct, r.aad)
	if err != nil {
		return fmt.Errorf("%w: chunk %d failed authentication", ErrCorrupt, r.counter)
	}
	r.pos += n
	r.counter++
	r.pending = pt
	if final {
		r.done = true
	}
	if r.prog != nil {
		r.prog(r.pos)
	}
	return nil
}

// drain reads and authenticates the rest of the stream and checks that it
// ended with a final-flag chunk.
func (r *chunkReader) drain() error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	if !r.done {
		return fmt.Errorf("%w: stream ends without a final chunk", ErrCorrupt)
	}
	return nil
}

// wipeBuffers zeroes the plaintext buffer (best effort).
func (r *chunkReader) wipeBuffers() {
	wipe(r.plain[:cap(r.plain)])
	r.pending = nil
}
