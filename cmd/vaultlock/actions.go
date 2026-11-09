package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Kangc3000/encryptfolder/internal/vault"
)

const (
	gib           = int64(1) << 30
	minFreeMargin = int64(64) << 20
	minPassword   = 8
	maxOwnerBytes = 64
	maxCapacityGB = int64(1) << 20
)

// friendly maps vault errors to plain sentences.
func friendly(err error) string {
	switch {
	case errors.Is(err, vault.ErrWrongPassword):
		return "Wrong password, or the vault is damaged."
	case errors.Is(err, vault.ErrEmpty):
		return "The vault is empty."
	case errors.Is(err, vault.ErrVaultEmptied):
		cause := errors.Unwrap(err)
		text := "unknown error"
		if errors.Is(err, vault.ErrTooLarge) {
			text = "the folder does not fit in the vault"
		} else if cause != nil {
			text = cause.Error()
		}
		return "Locking failed: " + text + ". Your folder is untouched, but the vault's previous locked copy had to be cleared. Fix the problem and lock again."
	case errors.Is(err, vault.ErrTooLarge):
		return "The folder does not fit in the vault. Remove some files, or Reset the vault with a larger capacity. Nothing was changed."
	case errors.Is(err, vault.ErrUnsupportedEntry), errors.Is(err, vault.ErrCaseCollision):
		return err.Error()
	case errors.Is(err, vault.ErrCorrupt):
		return "The vault data is damaged and cannot be read."
	case errors.Is(err, vault.ErrFolderExists):
		return "The folder already exists. Move or remove it first."
	case errors.Is(err, vault.ErrBadFormat):
		return "This file is not a VaultLock vault."
	}
	return err.Error()
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// clone returns a fresh copy of pw. Every vault call zeroes the slice it is
// given, so each call gets its own copy.
func clone(pw []byte) []byte { return append([]byte(nil), pw...) }

// ---- Validation (Initialize form) ----

// checkName validates a new vault name for dir. It returns the trimmed name
// and an empty string, or a message explaining what is wrong.
func checkName(dir, name string) (string, string) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return name, "The name must not be empty."
	case name == "." || name == ".." || strings.ContainsAny(name, `/\:*?"<>|`) || strings.ContainsRune(name, 0) || strings.HasSuffix(name, "."):
		return name, "The name must not contain path separators or any of  : * ? \" < > |  and must not end with a dot."
	case strings.EqualFold(filepath.Ext(name), vaultExt):
		return name, "Do not include \".vault\" in the name; it is added automatically."
	}
	if _, err := os.Lstat(filepath.Join(dir, name+vaultExt)); err == nil {
		return name, "A vault with that name already exists."
	}
	if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
		return name, "A file or folder with that name already exists."
	}
	return name, ""
}

// checkOwner validates the owner name: at most 64 bytes, no control characters.
func checkOwner(owner string) (string, string) {
	owner = strings.TrimSpace(owner)
	if len(owner) > maxOwnerBytes {
		return owner, fmt.Sprintf("The owner name is too long (at most %d bytes).", maxOwnerBytes)
	}
	if !utf8.ValidString(owner) {
		return owner, "The owner name contains invalid characters."
	}
	for _, r := range owner {
		if unicode.IsControl(r) {
			return owner, "The owner name must not contain control characters."
		}
	}
	return owner, ""
}

// parseGB parses a custom capacity in whole GB.
func parseGB(s string) (int64, string) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 1 || n > maxCapacityGB {
		return 0, "Enter the size as a whole number of GB, at least 1."
	}
	return n, ""
}

// checkFree verifies that a gb-sized vault leaves 64 MiB free on dir's volume.
func checkFree(dir string, gb int64) string {
	free, err := freeSpace(dir)
	if err != nil {
		return "Cannot determine free space on the drive: " + err.Error()
	}
	need := uint64(gb*gib + minFreeMargin)
	if free < need {
		return fmt.Sprintf("Not enough free space: %.1f GB available, %.1f GB needed (size plus 64 MB).",
			float64(free)/float64(gib), float64(need)/float64(gib))
	}
	return ""
}

// checkNewPassword enforces the length and match rules.
func checkNewPassword(p1, p2 string) string {
	if len(p1) < minPassword {
		return "The password must have at least 8 characters."
	}
	if p1 != p2 {
		return "The passwords do not match."
	}
	return ""
}

// ---- Operations (run off the UI goroutine) ----

// doCreate creates dir/name.vault and the empty folder. pw is zeroed.
func doCreate(dir, name string, gb int64, owner string, pw []byte, prog vault.Progress) (string, error) {
	defer zero(pw)
	vpath := filepath.Join(dir, name+vaultExt)
	folder := filepath.Join(dir, name)
	if err := vault.Create(vpath, gb*gib, owner, pw, vault.DefaultParams, prog); err != nil {
		return "", err
	}
	if err := os.Mkdir(folder, 0o755); err != nil {
		return "", fmt.Errorf("vault created, but the folder could not be created: %w", err)
	}
	return fmt.Sprintf("Vault \"%s\" created (%d GB). Put your files in the folder %s, then choose Lock.", name, gb, folder), nil
}

// doCheckSession reports whether vi's folder came from unlocking vi. pw is zeroed.
func doCheckSession(vi vaultInfo, pw []byte) (bool, error) {
	v, err := vault.Open(vi.Path)
	if err != nil {
		zero(pw)
		return false, err
	}
	return v.FolderMatchesSession(vi.Folder, pw)
}

// doLock locks vi. notice is true for a success that needs the user's
// attention (the folder changed and was kept). pw is zeroed.
func doLock(vi vaultInfo, pw []byte, prog vault.Progress) (msg string, notice bool, err error) {
	v, err := vault.Open(vi.Path)
	if err != nil {
		zero(pw)
		return "", false, err
	}
	err = v.Lock(vi.Folder, pw, true, prog)
	if errors.Is(err, vault.ErrFolderChanged) {
		return "Locked. The folder changed while it was being locked (a program may still have a file open), so it was kept. The vault holds the version from when locking started. Close any open files and lock again to remove the folder.", true, nil
	}
	if err != nil {
		if errors.Is(err, vault.ErrTooLarge) && !errors.Is(err, vault.ErrVaultEmptied) {
			return "", false, fmt.Errorf("The folder does not fit in the vault (%.1f GB). Nothing was changed.", float64(folderSize(vi.Folder))/float64(gib))
		}
		return "", false, err
	}
	return fmt.Sprintf("Vault \"%s\" is locked and the folder was removed.", vi.Name), false, nil
}

// doUnlock unlocks vi into its folder. pw is zeroed.
func doUnlock(vi vaultInfo, pw []byte, prog vault.Progress) (string, error) {
	v, err := vault.Open(vi.Path)
	if err != nil {
		zero(pw)
		return "", err
	}
	if _, err := os.Lstat(vi.Folder); err == nil {
		zero(pw)
		return "", vault.ErrFolderExists
	}
	err = v.Unlock(pw, vi.Folder, prog)
	if errors.Is(err, vault.ErrEmpty) {
		// Nothing stored yet: give the user an empty folder to start with.
		if merr := os.Mkdir(vi.Folder, 0o755); merr != nil {
			return "", merr
		}
		return fmt.Sprintf("Vault \"%s\" is empty. An empty folder %s was created.", vi.Name, vi.Folder), nil
	}
	if err != nil {
		if strings.Contains(err.Error(), ".partial") {
			return "", fmt.Errorf("%w. Rename or delete it manually, then unlock again.", err)
		}
		return "", err
	}
	return fmt.Sprintf("Vault \"%s\" is unlocked. Your files are in %s. Choose Lock when you are done.", vi.Name, vi.Folder), nil
}

// doReset destroys vi and, if asked, its folder. A non-empty warning means
// the vault was destroyed but the folder could not be deleted.
func doReset(vi vaultInfo, deleteFolder bool) (warning string, err error) {
	if err := vault.Destroy(vi.Path); err != nil {
		return "", err
	}
	if deleteFolder {
		if err := vault.RemoveFolder(vi.Folder); err != nil {
			return "The vault was destroyed, but the folder could not be deleted: " + err.Error(), nil
		}
	}
	return "", nil
}

// folderSize totals the regular-file sizes under dir (best effort).
func folderSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, e := d.Info(); e == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
		return nil
	})
	return n
}
