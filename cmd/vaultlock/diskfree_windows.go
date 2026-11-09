//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var procGetDiskFreeSpaceExW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// freeSpace returns the number of bytes available to the caller on the volume
// that contains dir.
func freeSpace(dir string) (uint64, error) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, totalFree uint64
	r, _, e := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, e
	}
	return avail, nil
}
