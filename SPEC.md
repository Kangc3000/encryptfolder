# VaultLock — design specification

Portable, no-install folder encryption for a USB drive. Two executables
(Windows `.exe`, macOS `.app`) live on the stick next to a fixed-size
encrypted vault file. The user double-clicks, picks an action, enters a
password. No drivers, no admin rights, nothing written to the host.

## Layout on the drive

```
USB/
  MyVault.vault        fixed-size encrypted file (always present once initialised)
  MyVault/             plain folder; exists only while unlocked
  Tools/
    VaultLock.exe      Windows (amd64, GUI subsystem, CGO_ENABLED=0)
    VaultLock.app/     macOS universal (arm64 + amd64) app bundle
```

The executable looks for `*.vault` files in its own directory and its
parent directory. If none is found the only action offered is Initialize.

## Actions

| Action | Behaviour |
|---|---|
| Initialize | Ask name, capacity (GB), password twice. Create `Name.vault` of exactly `capacity` bytes, header + random filler, and an empty `Name/` folder. |
| Lock | Pre-walk `Name/` (stat every entry, open every file, refuse special files, compute the exact stream size; refuse if it exceeds capacity — vault untouched). Pack the recorded entries into the vault (tar stream → chunked AES-256-GCM), fsync, update header meta, fsync, **verify by a full read-back decrypt** through a new uncached handle, comparing the entries read back with those recorded. Re-walk `Name/`: if anything changed, keep it (`ErrFolderChanged`, vault valid); otherwise delete exactly the recorded entries (see `remove.go` below). If the folder has no matching session marker, the UI asks before replacing a locked vault's content. |
| Unlock | Ask password, decrypt stream to `Name/` beside the vault. The data region is left untouched; meta is rewritten with a new session token (fresh meta nonce) and the token is written to `Name/.vaultlock-session`. Refuse if `Name/` already exists, or if two names differ only by letter case (`ErrCaseCollision`). |
| Reset | Confirm twice. Overwrite the header region with random bytes, delete the vault file, optionally delete `Name/` (separate confirmation), then run Initialize. |

Allowed-action matrix:

| vault exists | folder exists | actions offered |
|---|---|---|
| no | — | Initialize |
| yes | no | Unlock, Reset |
| yes | yes | Lock, Reset |

## Cryptography

All primitives from Go's standard library and `golang.org/x/crypto`.

* **Password → master key:** Argon2id, 32-byte output. Default params
  time=3, memory=256 MiB (262144 KiB), threads=4. Params are stored in the
  header so they can change in future versions. Open rejects headers
  outside time 1..10, memory ≤ 1 GiB (1048576 KiB), threads 1..16
  (`ErrBadFormat`).
* **Sub-keys:** HKDF-SHA256 from the master key:
  * `K_meta = HKDF(master, salt, "vaultlock/meta/v1")`
  * `K_data = HKDF(master, lockSalt, "vaultlock/data/v1")` — fresh per Lock
* **Cipher:** AES-256-GCM everywhere. Never reuse a (key, nonce) pair:
  the meta block gets a fresh random 12-byte nonce every rewrite (Lock,
  Unlock, reset); data chunks use a fresh `K_data` per Lock with a counter
  nonce.
* **Randomness:** `crypto/rand` only.
* **Password bytes** are zeroed after key derivation.

### Header (first 4096 bytes, plaintext except the meta block)

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `"EFVAULT1"` |
| 8 | 2 | format version = 2 (big-endian) |
| 10 | 4 | argon2 time |
| 14 | 4 | argon2 memory (KiB) |
| 18 | 1 | argon2 threads |
| 19 | 32 | argon2 salt |
| 51 | 8 | capacity in bytes (whole file size) |
| 59 | 12 | meta nonce |
| 71 | 57 | meta ciphertext (41 bytes plaintext + 16 tag) |
| 128 | … | zero padding to 4096 |

Meta plaintext (41 bytes): `state` (1: 0=empty, 1=locked), `usedLen`
(8, big-endian, bytes of ciphertext in the data region), `lockSalt` (16),
`sessionToken` (16). AAD for the meta block = header bytes 0..59.

`sessionToken` is drawn fresh by every Unlock and every Lock. Unlock writes
it, hex-encoded (32 characters), to `.vaultlock-session` (mode 0600) in
the root of the extracted folder; a Lock that keeps the folder rewrites the
marker with the new token. Lock never stores the marker but deletes it with
the folder. `FolderMatchesSession(folder, password)` is true when the vault
is empty or the marker matches the token, so the UI can warn before a
folder that did not come from this vault replaces its locked content.

A GCM failure on the meta block is reported as `ErrWrongPassword`
(the message to the user: "wrong password, or the vault is damaged").

### Data region (offset 4096 to end of file)

Filled with random bytes at Initialize. On Lock, a chunked stream is
written from offset 4096:

* plaintext chunk size 64 KiB; ciphertext chunk = 64 KiB + 16-byte tag
* nonce (12 bytes) = 3 zero bytes ‖ 8-byte big-endian chunk counter ‖
  1-byte flag (0x00 = more chunks follow, 0x01 = final chunk)
* AAD for every chunk = the 16-byte `lockSalt` from meta (binds the stream
  to the meta that describes it; not the meta nonce, which Unlock now
  refreshes without rewriting the data)
* the final chunk may be shorter than 64 KiB and may be empty
* on read: a chunk failing authentication → `ErrCorrupt`; reaching
  `usedLen` without a final-flag chunk → `ErrCorrupt` (truncation)

After the final chunk, Lock overwrites bytes from the new end to the
previous `usedLen` with random data so old ciphertext length is not
observable, fsyncs, rewrites meta (state=locked, usedLen, lockSalt,
sessionToken), fsyncs and closes the file. It then opens a new read handle
(`F_NOCACHE` on macOS) and reads back and authenticates the whole stream
before the plain folder is removed. Any failure after the first chunk was
written (overflow, read error, verification failure) resets the vault to
empty and returns `*EmptiedError` (`ErrVaultEmptied`); the folder is
untouched.

The plaintext stream is a `tar` archive (Go `archive/tar`, PAX format)
of the folder contents with paths relative to the folder root. No
compression. Symlinks are stored as symlinks; a named pipe, socket, device
or other special file makes Lock refuse before writing
(`*UnsupportedEntryError`). `.vaultlock-session` in the root and `._name`
AppleDouble files that have a sibling `name` are not stored. On extract,
paths are validated to stay inside the destination (reject `..` and
absolute paths), and names that differ only by letter case are refused.

### Capacity check before Lock

Exact size: every tar header (including PAX extended headers for long or
non-ASCII names) is encoded by a real `archive/tar` writer into a byte
counter, file sizes are added rounded up to 512 without reading the files,
then the tar trailer; then + 16 bytes per 64 KiB chunk (rounded up, at
least one chunk). If that + 4096 > capacity → `ErrTooLarge`, vault
untouched.

### Removing the folder after Lock (`remove.go`)

Lock records every stored entry (path, type, size, mtime to the second,
symlink target). After verification it walks the folder again; any added,
removed or changed entry (directories compared by type only) means nothing
is deleted and `ErrFolderChanged` is returned. Otherwise it deletes only
the recorded entries: files and symlinks, then the marker, then directories
deepest-first, then the root, each followed by its `._name` companion.
Deletion never uses `os.RemoveAll`: `removePath` retries each name in its
NFC and NFD spellings (macOS exFAT lists NFD but unlinks only the written
form) and a directory that is non-empty only because of `._` companions of
recorded names is cleaned and retried. A failure is reported as "locked
and verified, but removing the folder failed".

## Package layout

```
encryptfolder/
  go.mod                        module github.com/Kangc3000/encryptfolder
  SPEC.md
  README.md
  internal/vault/               crypto core, no UI
    vault.go  errors.go  header.go  stream.go  tar.go  record.go
    remove.go  verify_darwin.go  verify_other.go  *_test.go
  cmd/vaultlock/                dialog UI (github.com/ncruces/zenity)
    main.go  actions.go  discover.go
  build/
    build.sh                    produces dist/Tools/VaultLock.exe and dist/Tools/VaultLock.app
    Info.plist                  for the .app bundle
```

### `internal/vault` API

```go
package vault

type Params struct{ Time, MemoryKiB uint32; Threads uint8 }
var DefaultParams = Params{Time: 3, MemoryKiB: 262144, Threads: 4}

type State uint8
const ( StateEmpty State = 0; StateLocked State = 1 )

type Progress func(done, total int64) // may be nil

var (
    ErrWrongPassword = errors.New("wrong password, or the vault is damaged")
    ErrEmpty         = errors.New("the vault is empty")
    ErrTooLarge      = errors.New("the folder does not fit in the vault")
    ErrCorrupt       = errors.New("the vault is damaged")
    ErrFolderExists  = errors.New("the folder already exists")
    ErrBadFormat     = errors.New("not a VaultLock file")

    ErrUnsupportedEntry // *UnsupportedEntryError{Path}: pipe, socket or device; nothing written
    ErrVaultEmptied     // *EmptiedError{Cause}: failure after writing began; vault reset to empty
    ErrCaseCollision    // *CaseCollisionError{A, B}: Unlock, names differ only by case
    ErrFolderChanged    // Lock: vault valid, folder changed and was kept
)

// Create writes a new vault of exactly capacity bytes (>= 1 MiB).
func Create(path string, capacity int64, password []byte, p Params, prog Progress) error

// Open reads and validates the header. No password needed.
func Open(path string) (*Vault, error)

func (v *Vault) Path() string
func (v *Vault) Capacity() int64

// Status decrypts the meta block.
func (v *Vault) Status(password []byte) (State, int64, error)

// Lock encrypts folder into the vault; on success removes folder when removeSource is true.
func (v *Vault) Lock(folder string, password []byte, removeSource bool, prog Progress) error

// Unlock extracts the stream into destDir (created; must not exist).
func (v *Vault) Unlock(password []byte, destDir string, prog Progress) error

// FolderMatchesSession: true if the vault is empty or folder's marker matches.
func (v *Vault) FolderMatchesSession(folder string, password []byte) (bool, error)

// Destroy overwrites the header with random bytes and deletes the file.
func Destroy(path string) error
```

## UI (cmd/vaultlock)

* Native dialogs via `github.com/ncruces/zenity` (pure Go; Win32 dialogs
  on Windows, osascript dialogs on macOS). Flow: action list → inputs →
  password → progress → result message.
* Password dialogs use hidden input. Initialize asks twice and rejects a
  mismatch or fewer than 8 characters.
* Progress dialog during Create, Lock (write and verify passes), Unlock.
* Every error is shown in a dialog with the error text; never a panic.
* Windows build flag `-ldflags "-s -w -H windowsgui"`; macOS binary is
  wrapped in `VaultLock.app` so double-click does not open Terminal.

## Build

```
build/build.sh
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" -o dist/Tools/VaultLock.exe ./cmd/vaultlock
  GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/VaultLock-arm64 ./cmd/vaultlock
  GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/VaultLock-amd64 ./cmd/vaultlock
  lipo -create -output dist/Tools/VaultLock.app/Contents/MacOS/VaultLock build/VaultLock-arm64 build/VaultLock-amd64
  cp build/Info.plist dist/Tools/VaultLock.app/Contents/
```

## Known limitations (document in README)

* Lock deletes the plain folder with a normal delete; flash wear-levelling
  means remnants may be forensically recoverable. Unlock only what you
  need, relock promptly.
* Opening a file from the unlocked folder with another application may
  leave temporary copies on the host computer.
* Capacity is fixed at Initialize; Reset is the only way to change it.
* Unsigned executables: Windows SmartScreen may warn once; macOS may need
  right-click → Open if the bundle acquires a quarantine flag.
