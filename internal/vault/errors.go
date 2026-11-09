package vault

import (
	"errors"
	"fmt"
)

var (
	ErrWrongPassword = errors.New("wrong password, or the vault is damaged")
	ErrEmpty         = errors.New("the vault is empty")
	ErrTooLarge      = errors.New("the folder does not fit in the vault")
	ErrCorrupt       = errors.New("the vault is damaged")
	ErrFolderExists  = errors.New("the folder already exists")
	ErrBadFormat     = errors.New("not a VaultLock file")

	// ErrUnsupportedEntry is matched by *UnsupportedEntryError.
	ErrUnsupportedEntry = errors.New("the folder contains a file that cannot be stored (named pipe, socket or device)")
	// ErrVaultEmptied is matched by *EmptiedError.
	ErrVaultEmptied = errors.New("the lock failed and the vault's previous locked copy had to be cleared")
	// ErrCaseCollision is matched by *CaseCollisionError.
	ErrCaseCollision = errors.New("the vault contains two names that differ only by letter case")
	// ErrFolderChanged is returned by Lock when the folder changed while it
	// was being locked. The vault is valid and holds the version from the
	// start of the lock; the folder was kept.
	ErrFolderChanged = errors.New("the folder changed while it was being locked; the vault holds the version from the start of the lock and the folder was kept")
)

// UnsupportedEntryError reports a named pipe, socket, device or other
// special file found before anything was written.
type UnsupportedEntryError struct {
	Path string
}

func (e *UnsupportedEntryError) Error() string {
	return ErrUnsupportedEntry.Error() + ": " + e.Path
}

func (e *UnsupportedEntryError) Is(target error) bool { return target == ErrUnsupportedEntry }

// EmptiedError reports a Lock that failed after the old stream had started
// to be overwritten. The vault was reset to empty; the folder is untouched.
// Cause is the original failure (for example ErrTooLarge).
type EmptiedError struct {
	Cause error
}

func (e *EmptiedError) Error() string {
	return "the lock failed and the vault's previous locked copy had to be cleared; the folder is untouched: " + fmt.Sprint(e.Cause)
}

func (e *EmptiedError) Is(target error) bool { return target == ErrVaultEmptied }

func (e *EmptiedError) Unwrap() error { return e.Cause }

// CaseCollisionError reports two archive entries whose names differ only by
// letter case.
type CaseCollisionError struct {
	A, B string
}

func (e *CaseCollisionError) Error() string {
	return fmt.Sprintf("the vault contains two names that differ only by letter case, which this disk cannot store: %s and %s", e.A, e.B)
}

func (e *CaseCollisionError) Is(target error) bool { return target == ErrCaseCollision }
