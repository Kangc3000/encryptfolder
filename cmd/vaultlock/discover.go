package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const vaultExt = ".vault"

// Action names shown in the action list.
const (
	actInitialize = "Initialize (create a new vault)"
	actLock       = "Lock (encrypt the folder)"
	actUnlock     = "Unlock (decrypt into the folder)"
	actReset      = "Reset (destroy the vault and start over)"
)

// vaultInfo describes one vault file found next to the program.
type vaultInfo struct {
	Path         string // full path of Name.vault
	Folder       string // full path of Name (companion folder)
	Name         string // Name without the .vault suffix
	Dir          string // directory containing the vault
	FolderExists bool
}

// searchDirs returns the directories that are scanned for vaults: the
// directory holding the executable (or, on macOS, the directory holding
// VaultLock.app) and its parent.
func searchDirs() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	dir := filepath.Dir(exe)
	// Inside an .app bundle: walk up to the directory that contains the .app.
	for d := dir; ; {
		if strings.HasSuffix(strings.ToLower(filepath.Base(d)), ".app") {
			dir = filepath.Dir(d)
			break
		}
		p := filepath.Dir(d)
		if p == d {
			break
		}
		d = p
	}
	dirs := []string{dir}
	if p := filepath.Dir(dir); p != dir {
		dirs = append(dirs, p)
	}
	return dirs
}

// newVaultDir is where Initialize puts a new vault: the parent of the
// directory holding the tools, i.e. the root of the USB drive.
func newVaultDir() string {
	dirs := searchDirs()
	if len(dirs) == 0 {
		wd, _ := os.Getwd()
		return wd
	}
	return dirs[len(dirs)-1]
}

// discoverVaults lists *.vault files in dirs.
func discoverVaults(dirs []string) []vaultInfo {
	seen := map[string]bool{}
	var out []vaultInfo
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || strings.HasPrefix(n, ".") || !strings.EqualFold(filepath.Ext(n), vaultExt) {
				continue
			}
			p := filepath.Join(d, n)
			if seen[p] {
				continue
			}
			seen[p] = true
			name := strings.TrimSuffix(n, filepath.Ext(n))
			folder := filepath.Join(d, name)
			fi, err := os.Stat(folder)
			out = append(out, vaultInfo{
				Path:         p,
				Folder:       folder,
				Name:         name,
				Dir:          d,
				FolderExists: err == nil && fi.IsDir(),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// allowedActions implements the allowed-action matrix. v == nil means no
// vault exists.
func allowedActions(v *vaultInfo) []string {
	switch {
	case v == nil:
		return []string{actInitialize}
	case v.FolderExists:
		return []string{actLock, actReset}
	default:
		return []string{actUnlock, actReset}
	}
}

// vaultLabels returns one list label per vault. Names that occur more than
// once are disambiguated with their directory; labels are always unique.
func vaultLabels(vs []vaultInfo) []string {
	count := map[string]int{}
	for _, v := range vs {
		count[v.Name]++
	}
	labels := make([]string, len(vs))
	used := map[string]bool{}
	for i, v := range vs {
		l := v.Name
		if count[v.Name] > 1 {
			l = fmt.Sprintf("%s  (%s)", v.Name, v.Dir)
		}
		for used[l] {
			l += " "
		}
		used[l] = true
		labels[i] = l
	}
	return labels
}
