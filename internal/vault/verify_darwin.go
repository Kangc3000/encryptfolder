//go:build darwin

package vault

import (
	"os"

	"golang.org/x/sys/unix"
)

// noCache asks the kernel not to serve reads of f from the buffer cache
// (F_NOCACHE), so verification reads what is on the device. Best effort.
func noCache(f *os.File) {
	_, _ = unix.FcntlInt(f.Fd(), unix.F_NOCACHE, 1)
}
