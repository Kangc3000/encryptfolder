# VaultLock

Portable, no-install folder encryption for a USB drive. Double-click the
program: a small window shows the vault on the drive (name, owner, whether
it is locked or unlocked, capacity, and when it was created, last unlocked
and last locked) above four large buttons: Initialize, Unlock, Lock and
Reset. A fixed-size encrypted vault file
holds your folder; the plain folder exists only while the vault is unlocked.
Nothing is installed and nothing is written to the host computer.

## Putting it on a USB drive

Build (see below), then copy the contents of `dist/Tools` to the drive:

```
USB/
  Tools/
    VaultLock.exe      Windows
    VaultLock.app      macOS (Apple silicon and Intel)
```

Run the program from `Tools`. Vaults live next to `Tools` (the drive root);
the program also finds `*.vault` files in its own folder.

## Actions

Each action asks for what it needs inside the same window (no pop-up
dialogs); Enter confirms and Esc cancels. Long operations show a progress
bar, and the outcome appears as a green, amber or red message at the top of
the window. If the drive holds several vaults, pick one from the row of
names above the status card.

* **Initialize** - choose a name, an owner name (shown on the status card;
  up to 64 bytes), a capacity and a password (twice). Creates
  `Name.vault` (exactly that many bytes) and an empty `Name/` folder.
* **Lock** - encrypts `Name/` into the vault, checks it by decrypting it
  again, then deletes `Name/`.
* **Unlock** - asks the password and restores `Name/` beside the vault.
* **Reset** - destroys the vault (two confirmations, plus a choice to delete
  `Name/` too if it exists) and opens Initialize with the same name. Use it
  to change the capacity.

Only the actions that make sense are enabled: with no vault, Initialize;
vault but no folder, Unlock and Reset; vault and folder, Lock and Reset.

## Security design

AES-256-GCM with a key derived from your password by Argon2id; the vault
file has a fixed size and a random-filled data region so its content size
is not visible. Full details are in [SPEC.md](SPEC.md). There is no password
recovery.

## Building

```
build/build.sh
```

Needs Go; produces `dist/Tools/VaultLock.exe` and
`dist/Tools/VaultLock.app`. The window is drawn with [Gio](https://gioui.org).
The Windows build is pure Go (`CGO_ENABLED=0`), but the macOS build uses
cgo, so it needs clang from the Xcode Command Line Tools
(`xcode-select --install`), which also provides `lipo` for the universal
binary. Build the macOS app on a Mac.

## Known limitations

* Lock deletes the plain folder with a normal delete; flash wear-levelling
  means remnants may be forensically recoverable. Unlock only what you
  need, relock promptly.
* Opening a file from the unlocked folder with another application may
  leave temporary copies on the host computer.
* Capacity is fixed at Initialize; Reset is the only way to change it.
* Unsigned executables: Windows SmartScreen may warn once; macOS may need
  right-click → Open if the bundle acquires a quarantine flag.
* Executables on the stick can be tampered with by a malicious host
  computer. Keep a copy of the Tools folder on a trusted computer and
  compare file hashes if in doubt.
* Symlinks that Windows cannot create are skipped on Unlock, and would be
  dropped by the next Lock.
* A crash during Unlock can leave a plaintext `<name>.partial` folder next
  to the vault. Delete or rename it manually before unlocking again.

## If something goes wrong

* **"Locked. The folder changed while it was being locked..."** The vault
  is fine and holds the version of your files from the moment locking
  started. The folder was kept because something (often a program with a
  file still open) changed it meanwhile. Close open files and Lock again to
  remove the folder.
* **"Locking failed ... the vault's previous locked copy had to be
  cleared."** Your folder is untouched, but the older copy stored in the
  vault was erased while Locking was under way. Fix the cause named in the
  message (for example, make the folder smaller) and Lock again. Until
  then the vault does not hold your files, so keep the folder.
