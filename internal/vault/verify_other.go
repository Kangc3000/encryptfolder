//go:build !darwin

package vault

import "os"

// noCache is a no-op outside macOS.
func noCache(*os.File) {}
