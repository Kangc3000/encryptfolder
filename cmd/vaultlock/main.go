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
	if !acquireSingleInstance() {
		_ = zenity.Info("VaultLock is already running. Look for its window.", zenity.Title(appTitle))
		return
	}
	run()
}

// pick shows a list with the first item pre-selected. An empty choice (OK
// with nothing selected) is treated like Cancel so the loop never repeats
// the same dialog without the user having chosen anything.
func pick(prompt string, items []string) (string, error) {
	choice, err := zenity.List(prompt, items, zenity.Title(appTitle),
		zenity.DefaultItems(items[0]), zenity.DisallowEmpty())
	if err == nil && choice == "" {
		return "", zenity.ErrCanceled
	}
	return choice, err
}

func run() {
	for {
		vaults, derr := discoverVaults(searchDirs())
		if derr != nil {
			showError(derr)
			return
		}

		var cur *vaultInfo
		switch len(vaults) {
		case 0:
		case 1:
			cur = &vaults[0]
		default:
			names := vaultLabels(vaults)
			choice, err := pick("Choose a vault:", names)
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
		choice, err := pick(prompt, allowedActions(cur))
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
