// Package vault implements the VaultLock container format: a fixed-size
// file holding one password-protected, AES-256-GCM encrypted tar archive of
// a folder.
//
// # File layout
//
// A vault is exactly Capacity bytes long. The first 4096 bytes are the
// header; everything after that is the data region.
//
//	offset size field
//	     0    8 magic "EFVAULT1"
//	     8    2 format version = 3 (big-endian)
//	    10    4 Argon2id time
//	    14    4 Argon2id memory (KiB)
//	    18    1 Argon2id threads
//	    19   32 Argon2id salt
//	    51    8 capacity in bytes (whole file size)
//	    59   12 meta nonce
//	    71   57 meta ciphertext (41 bytes plaintext + 16-byte GCM tag)
//	   128   64 owner (UTF-8, zero-padded; label block)
//	   192    8 created (unix seconds, big-endian)
//	   200    8 last unlocked (unix seconds; 0 = never)
//	   208    8 last locked (unix seconds; 0 = never)
//	   216    … zero padding to 4096
//
// The meta plaintext is state (1 byte: 0 empty, 1 locked), usedLen
// (8 bytes, big-endian: ciphertext bytes in the data region), lockSalt
// (16 bytes) and sessionToken (16 bytes; also written, hex-encoded, to
// .vaultlock-session in the folder Unlock creates). It is sealed with K_meta under a fresh random nonce on every
// rewrite, with header bytes 0..59 followed by the label block (bytes
// 128..216) as additional data. Failure to open it is reported as
// ErrWrongPassword.
//
// The label block is plaintext so Label can show the owner and dates without
// the password; it is authenticated only when a password is used, so it is
// for display only. Create sets created, Unlock sets last unlocked and Lock
// sets last locked, each in the same write as the meta block sealed over it.
//
// # Keys
//
//	master = Argon2id(password, salt, time, memory, threads, 32)
//	K_meta = HKDF-SHA256(master, salt,     "vaultlock/meta/v1")
//	K_data = HKDF-SHA256(master, lockSalt, "vaultlock/data/v1")
//
// lockSalt is drawn fresh on every Lock, so every locked stream uses a new
// K_data and its counter nonces are never reused.
//
// # Data stream
//
// The plaintext is a PAX tar archive of the folder contents (paths relative
// to the folder root; regular files, directories and symlinks; Lock refuses
// other file types). It is cut into 64 KiB chunks, each sealed with K_data:
//
//	nonce = 3 zero bytes || 8-byte big-endian chunk counter || flag (0x00 more, 0x01 final)
//	AAD   = the 16-byte lockSalt from the meta block
//
// The final chunk may be short or empty. On read, the chunk that ends at
// usedLen must carry the final flag and every other chunk must not, so
// truncation, extension, reordering and splicing all fail authentication
// (ErrCorrupt). Bytes after the stream are random filler: Create fills the
// data region with random bytes, and Lock overwrites any tail of an older,
// longer stream with fresh random bytes.
//
// Lock always authenticates the whole new stream by reading it back through
// a new, uncached handle, compares the entries with those it wrote, and then
// deletes only those entries, and only if the folder did not change. Unlock extracts into destDir+".partial" and
// renames it into place only after the entire stream has been authenticated.
//
// Password slices passed to Create, Status, Lock, Unlock and
// FolderMatchesSession are zeroed
// before those functions return, and derived keys are zeroed after use.
// This is best effort: the Go runtime may have copied the bytes (for
// example during garbage collection or inside the AES key schedule), so it
// cannot be guaranteed.
package vault
