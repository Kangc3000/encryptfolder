//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// acquireSingleInstance returns false if another VaultLock is already
// running for this user. The lock is released automatically when the
// process exits, however it exits.
func acquireSingleInstance() bool {
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "vaultlock.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return true // cannot lock; do not block the user
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return false
	}
	instanceLock = f // keep the descriptor open for the life of the process
	return true
}

var instanceLock *os.File
