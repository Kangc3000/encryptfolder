// VaultLock: portable folder encryption with native dialogs.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ncruces/zenity"
)

const appTitle = "VaultLock"

func main() {
	defer func() {
		if r := recover(); r != nil {
			showError(fmt.Errorf("unexpected error: %v", r))
			os.Exit(1)
		}
	}()
	run()
}

func run() {
	for {
		vaults := discoverVaults(searchDirs())

		var cur *vaultInfo
		switch len(vaults) {
		case 0:
		case 1:
			cur = &vaults[0]
		default:
			names := vaultLabels(vaults)
			choice, err := zenity.List("Choose a vault:", names, zenity.Title(appTitle))
			if err != nil {
				if !errors.Is(err, zenity.ErrCanceled) {
					showError(err)
				}
				return
			}
			for i := range vaults {
				if names[i] == choice {
					cur = &vaults[i]
					break
				}
			}
			if cur == nil {
				return
			}
		}

		prompt := "No vault found. What would you like to do?"
		if cur != nil {
			state := "locked"
			if cur.FolderExists {
				state = "unlocked"
			}
			prompt = fmt.Sprintf("Vault \"%s\" is %s. What would you like to do?", cur.Name, state)
		}
		choice, err := zenity.List(prompt, allowedActions(cur), zenity.Title(appTitle))
		if err != nil {
			if errors.Is(err, zenity.ErrCanceled) {
				if len(vaults) > 1 {
					continue // back to the vault list
				}
				return
			}
			showError(err)
			return
		}

		var aerr error
		switch choice {
		case actInitialize:
			aerr = initialize(newVaultDir(), "")
		case actLock:
			aerr = lockVault(*cur)
		case actUnlock:
			aerr = unlockVault(*cur)
		case actReset:
			aerr = resetVault(*cur)
		}
		if aerr != nil && !errors.Is(aerr, zenity.ErrCanceled) {
			showError(aerr)
		}
	}
}
