// VaultLock: portable folder encryption with a small Gio window.
package main

import (
	"os"

	"gioui.org/app"
	"gioui.org/unit"
)

const appTitle = "VaultLock"

func main() {
	w := new(app.Window)
	w.Option(app.Title(appTitle), app.Size(unit.Dp(640), unit.Dp(460)), app.MinSize(unit.Dp(520), unit.Dp(400)))
	u := newUI(w)
	if !acquireSingleInstance() {
		u.fatal = "VaultLock is already running. Look for its window."
	} else {
		u.refresh()
	}
	go func() {
		u.loop()
		// The window is gone. Let a running Lock/Unlock/Create finish so the
		// vault is never left half-written, then exit.
		u.ops.Wait()
		os.Exit(0)
	}()
	app.Main()
}
