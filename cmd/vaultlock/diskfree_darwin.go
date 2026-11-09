//go:build darwin

package main

import "syscall"

// freeSpace returns the number of bytes available to an unprivileged user on
// the volume that contains dir.
func freeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
