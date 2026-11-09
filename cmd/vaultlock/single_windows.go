//go:build windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// acquireSingleInstance returns false if another VaultLock is already
// running. The lock file is opened with no sharing, so a second open fails
// with a sharing violation; Windows releases it when the process exits.
func acquireSingleInstance() bool {
	name, err := syscall.UTF16PtrFromString(filepath.Join(os.TempDir(), "vaultlock.lock"))
	if err != nil {
		return true
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == 32 { // ERROR_SHARING_VIOLATION
			return false
		}
		return true
	}
	instanceLock = h // keep the handle open for the life of the process
	return true
}

var instanceLock syscall.Handle
