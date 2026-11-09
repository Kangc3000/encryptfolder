package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Kangc3000/encryptfolder/internal/vault"
	"github.com/ncruces/zenity"
)

const (
	gib           = int64(1) << 30
	minFreeMargin = int64(64) << 20
	minPassword   = 8
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

func showError(err error) {
	_ = zenity.Error(friendly(err), zenity.Title(appTitle+" - error"))
}

func showInfo(msg string) {
	_ = zenity.Info(msg, zenity.Title(appTitle))
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// askPassword shows a hidden-input dialog. The caller must zero the result.
func askPassword(title string) ([]byte, error) {
	_, pw, err := zenity.Password(zenity.Title(title))
	if err != nil {
		return nil, err
	}
	return []byte(pw), nil
}

// askNewPassword asks twice and enforces length and match.
func askNewPassword() ([]byte, error) {
	for {
		p1, err := askPassword("Choose a password (at least 8 characters)")
		if err != nil {
			return nil, err
		}
		if len(p1) < minPassword {
			zero(p1)
			_ = zenity.Error("The password must have at least 8 characters.", zenity.Title(appTitle))
			continue
		}
		p2, err := askPassword("Repeat the password")
		if err != nil {
			zero(p1)
			return nil, err
		}
		same := string(p1) == string(p2)
		zero(p2)
		if !same {
			zero(p1)
			_ = zenity.Error("The passwords do not match.", zenity.Title(appTitle))
			continue
		}
		return p1, nil
	}
}

// progress wraps a zenity progress dialog and adapts it to vault.Progress.
type progress struct {
	dlg  zenity.ProgressDialog
	text string
	last int
	prev int64
}

func newProgress(title, text string) *progress {
	d, err := zenity.Progress(zenity.Title(title), zenity.MaxValue(100), zenity.NoCancel())
	if err != nil {
		return &progress{} // run without a dialog
	}
	p := &progress{dlg: d, last: -1}
	p.setText(text)
	return p
}

func (p *progress) setText(t string) {
	p.text = t
	if p.dlg != nil {
		_ = p.dlg.Text(t)
	}
}

// callback is a vault.Progress. Lock reports a single bar whose first half
// is the write pass and second half the read-back verification, so when
// verifyText is non-empty the text switches once done passes the midpoint.
func (p *progress) callback(verifyText string) vault.Progress {
	return func(done, total int64) {
		if p.dlg == nil || total <= 0 {
			return
		}
		if verifyText != "" && p.text != verifyText && done*2 >= total {
			p.setText(verifyText)
		}
		p.prev = done
		pct := int(done * 100 / total)
		if pct > 100 {
			pct = 100
		}
		if pct != p.last {
			p.last = pct
			_ = p.dlg.Value(pct)
		}
	}
}

func (p *progress) close() {
	if p.dlg != nil {
		_ = p.dlg.Complete()
		_ = p.dlg.Close()
	}
}

// ---- Initialize ----

func askName(dir, preset string) (string, error) {
	for {
		opts := []zenity.Option{zenity.Title(appTitle + " - vault name")}
		if preset != "" {
			opts = append(opts, zenity.EntryText(preset))
		}
		name, err := zenity.Entry("Name for the new vault:", opts...)
		if err != nil {
			return "", err
		}
		name = strings.TrimSpace(name)
		preset = name
		switch {
		case name == "":
			_ = zenity.Error("The name must not be empty.", zenity.Title(appTitle))
		case name == "." || name == ".." || strings.ContainsAny(name, `/\:*?"<>|`) || strings.ContainsRune(name, 0) || strings.HasSuffix(name, "."):
			_ = zenity.Error("The name must not contain path separators or any of  : * ? \" < > |  and must not end with a dot.", zenity.Title(appTitle))
		case strings.EqualFold(filepath.Ext(name), vaultExt):
			_ = zenity.Error("Do not include \".vault\" in the name; it is added automatically.", zenity.Title(appTitle))
		default:
			if _, err := os.Lstat(filepath.Join(dir, name+vaultExt)); err == nil {
				_ = zenity.Error("A vault with that name already exists.", zenity.Title(appTitle))
				continue
			}
			if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
				_ = zenity.Error("A file or folder with that name already exists.", zenity.Title(appTitle))
				continue
			}
			return name, nil
		}
	}
}

func askCapacityGB() (int64, error) {
	const custom = "Custom…"
	sizes := []string{"1 GB", "2 GB", "5 GB", "10 GB", "20 GB", "50 GB", custom}
	choice, err := zenity.List("Vault capacity:", sizes, zenity.Title(appTitle+" - capacity"))
	if err != nil {
		return 0, err
	}
	if choice != custom {
		n, err := strconv.ParseInt(strings.TrimSuffix(choice, " GB"), 10, 64)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	for {
		s, err := zenity.Entry("Capacity in whole GB (1 or more):", zenity.Title(appTitle+" - capacity"))
		if err != nil {
			return 0, err
		}
		n, perr := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if perr != nil || n < 1 || n > 1<<20 {
			_ = zenity.Error("Enter a whole number of GB, at least 1.", zenity.Title(appTitle))
			continue
		}
		return n, nil
	}
}

// initialize creates a new vault in dir. presetName pre-fills the name box.
func initialize(dir, presetName string) error {
	name, err := askName(dir, presetName)
	if err != nil {
		return err
	}
	var gb int64
	for {
		gb, err = askCapacityGB()
		if err != nil {
			return err
		}
		free, ferr := freeSpace(dir)
		if ferr != nil {
			return fmt.Errorf("cannot determine free space on the drive: %w", ferr)
		}
		need := uint64(gb*gib + minFreeMargin)
		if free < need {
			_ = zenity.Error(fmt.Sprintf("Not enough free space: %.1f GB available, %.1f GB needed (capacity plus 64 MB).",
				float64(free)/float64(gib), float64(need)/float64(gib)), zenity.Title(appTitle))
			continue
		}
		break
	}
	pw, err := askNewPassword()
	if err != nil {
		return err
	}
	defer zero(pw)

	vpath := filepath.Join(dir, name+vaultExt)
	folder := filepath.Join(dir, name)

	pr := newProgress(appTitle+" - creating vault", "Creating vault…")
	err = vault.Create(vpath, gb*gib, pw, vault.DefaultParams, pr.callback(""))
	pr.close()
	if err != nil {
		return err
	}
	if err := os.Mkdir(folder, 0o755); err != nil {
		return fmt.Errorf("vault created, but the folder could not be created: %w", err)
	}
	showInfo(fmt.Sprintf("Vault \"%s\" created (%d GB).\n\nPut your files in the folder \"%s\", then run VaultLock and choose Lock.", name, gb, folder))
	return nil
}

// ---- Lock ----

func lockVault(vi vaultInfo) error {
	v, err := vault.Open(vi.Path)
	if err != nil {
		return err
	}
	pw, err := askPassword("Password for \"" + vi.Name + "\"")
	if err != nil {
		return err
	}
	defer zero(pw)
	pwStr := string(pw)

	ok, err := v.FolderMatchesSession(vi.Folder, []byte(pwStr))
	if err != nil {
		return err
	}
	if !ok {
		if err := zenity.Question(
			fmt.Sprintf("This folder was not produced by unlocking \"%s\". Locking will REPLACE whatever is currently stored in the vault with this folder's contents. Continue?", vi.Name),
			zenity.Title(appTitle+" - lock"), zenity.WarningIcon,
			zenity.OKLabel("Replace vault contents"), zenity.CancelLabel("Cancel")); err != nil {
			return err
		}
	}

	pr := newProgress(appTitle+" - locking", "Encrypting…")
	err = v.Lock(vi.Folder, []byte(pwStr), true, pr.callback("Verifying…"))
	pr.close()
	if errors.Is(err, vault.ErrFolderChanged) {
		showInfo("Locked. The folder changed while it was being locked (a program may still have a file open), so it was kept. The vault holds the version from when locking started. Close any open files and lock again to remove the folder.")
		return nil
	}
	if err != nil {
		if errors.Is(err, vault.ErrTooLarge) && !errors.Is(err, vault.ErrVaultEmptied) {
			return fmt.Errorf("The folder does not fit in the vault (%.1f GB). Nothing was changed.", folderSizeGB(vi.Folder))
		}
		return err
	}
	showInfo(fmt.Sprintf("Vault \"%s\" is locked and the folder was removed.", vi.Name))
	return nil
}

// ---- Unlock ----

func unlockVault(vi vaultInfo) error {
	v, err := vault.Open(vi.Path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(vi.Folder); err == nil {
		return vault.ErrFolderExists
	}
	pw, err := askPassword("Password for \"" + vi.Name + "\"")
	if err != nil {
		return err
	}
	defer zero(pw)

	pr := newProgress(appTitle+" - unlocking", "Decrypting…")
	err = v.Unlock(pw, vi.Folder, pr.callback(""))
	pr.close()
	if errors.Is(err, vault.ErrEmpty) {
		// Nothing stored yet: give the user an empty folder to start with.
		if merr := os.Mkdir(vi.Folder, 0o755); merr != nil {
			return merr
		}
		showInfo(fmt.Sprintf("Vault \"%s\" is empty. An empty folder \"%s\" was created.", vi.Name, vi.Folder))
		return nil
	}
	if err != nil {
		if strings.Contains(err.Error(), ".partial") {
			return fmt.Errorf("%w\n\nRename or delete it manually, then unlock again.", err)
		}
		return err
	}
	showInfo(fmt.Sprintf("Vault \"%s\" is unlocked.\n\nYour files are in:\n%s\n\nChoose Lock when you are done.", vi.Name, vi.Folder))
	return nil
}

// ---- Reset ----

func resetVault(vi vaultInfo) error {
	if err := zenity.Question(
		fmt.Sprintf("Reset destroys the vault \"%s\". Everything stored in it becomes permanently unrecoverable.\n\nContinue?", vi.Name),
		zenity.Title(appTitle+" - reset"), zenity.WarningIcon, zenity.OKLabel("Continue"), zenity.CancelLabel("Cancel")); err != nil {
		return err
	}
	if err := zenity.Question(
		"Are you really sure? This cannot be undone.",
		zenity.Title(appTitle+" - reset"), zenity.WarningIcon, zenity.OKLabel("Destroy vault"), zenity.CancelLabel("Cancel")); err != nil {
		return err
	}
	deleteFolder := false
	if _, err := os.Lstat(vi.Folder); err == nil {
		err := zenity.Question(
			fmt.Sprintf("The unlocked folder \"%s\" still exists. Delete it too?\n\nIf you keep it, its files stay on the drive unencrypted.", vi.Folder),
			zenity.Title(appTitle+" - reset"), zenity.WarningIcon, zenity.OKLabel("Delete folder"), zenity.CancelLabel("Keep folder"))
		switch {
		case err == nil:
			deleteFolder = true
		case errors.Is(err, zenity.ErrCanceled):
		default:
			return err
		}
	}
	if err := vault.Destroy(vi.Path); err != nil {
		return err
	}
	if deleteFolder {
		if err := vault.RemoveFolder(vi.Folder); err != nil {
			showError(fmt.Errorf("the vault was destroyed, but the folder could not be deleted: %w", err))
		}
	}
	return initialize(vi.Dir, vi.Name)
}

// folderSizeGB totals the regular-file sizes under dir, in GB (best effort).
func folderSizeGB(dir string) float64 {
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
	return float64(n) / float64(gib)
}
