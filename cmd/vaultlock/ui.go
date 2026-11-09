package main

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"sync"
	"sync/atomic"
	"time"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/io/event"
	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"golang.org/x/exp/shiny/materialdesign/icons"

	"github.com/Kangc3000/encryptfolder/internal/vault"
)

type (
	C = layout.Context
	D = layout.Dimensions
)

// Colours (light theme).
var (
	colBg        = rgb(0xf3f5f8)
	colCard      = rgb(0xffffff)
	colBorder    = rgb(0xd5dae1)
	colText      = rgb(0x1f2933)
	colMuted     = rgb(0x616e7c)
	colAccent    = rgb(0x2f6fde)
	colChip      = rgb(0xe4e8ee)
	colChipHover = rgb(0xd3d9e2)
	colWhite     = rgb(0xffffff)

	colInit   = rgb(0x2e8b57)
	colUnlock = rgb(0x2f6fde)
	colLock   = rgb(0x4b4fc4)
	colReset  = rgb(0xc0392b)

	colOKBg, colOKFg         = rgb(0xe3f4e8), rgb(0x1e4620)
	colNoticeBg, colNoticeFg = rgb(0xfff3dc), rgb(0x663c00)
	colErrBg, colErrFg       = rgb(0xfdecea), rgb(0x611a15)

	colBadgeLocked   = rgb(0x2e8b57)
	colBadgeUnlocked = rgb(0xd98a00)
	colBadgeEmpty    = rgb(0x8a94a3)
)

func rgb(c uint32) color.NRGBA {
	return color.NRGBA{R: uint8(c >> 16), G: uint8(c >> 8), B: uint8(c), A: 0xff}
}

type mode int

const (
	modeHome mode = iota
	modeInit
	modeUnlock
	modeLock
	modeLockConfirm
	modeReset1
	modeReset2
)

type bannerKind int

const (
	bannerNone bannerKind = iota
	bannerOK
	bannerNotice
	bannerError
)

// vaultEntry is a discovered vault plus what its header says.
type vaultEntry struct {
	info     vaultInfo
	label    vault.Label
	capacity int64
	err      error // Open failed
}

// sizeInfo is a lazily computed folder size.
type sizeInfo struct {
	done  bool
	bytes int64
}

var sizeChoices = []int64{1, 2, 5, 10, 20, 50}

type ui struct {
	w     *app.Window
	th    *material.Theme
	inbox chan func() // closures run on the UI goroutine
	ops   sync.WaitGroup

	// discovery
	loading bool
	fatal   string
	vaults  []vaultEntry
	sel     int
	vChips  []widget.Clickable
	vList   widget.List
	sizes   map[string]*sizeInfo

	// page state
	mode        mode
	target      vaultInfo // vault the current form acts on
	targetOwner string
	bannerKind  bannerKind
	bannerText  string
	bannerClose widget.Clickable
	scroll      widget.List
	formErr     string
	focus       *widget.Editor // editor to focus on the next frame

	btnInit, btnUnlock, btnLock, btnReset widget.Clickable
	icInit, icUnlock, icLock, icReset     *widget.Icon

	// forms
	edName, edOwner, edCustom, edPw1, edPw2, edPw widget.Editor
	sizeBtns                                      []widget.Clickable // sizeChoices plus "Custom"
	sizeSel                                       int                // index into sizeBtns
	initDir                                       string
	freeText                                      string
	submit, cancel                                widget.Clickable
	delFolder                                     widget.Bool
	pendingPw                                     []byte // Lock: password kept across the replace warning

	// long operation
	busy       bool
	busyText   string
	verifyText string // switch busyText to this once done*2 >= total
	progDone   atomic.Int64
	progTotal  atomic.Int64
	progPermil atomic.Int64
}

func mustIcon(data []byte) *widget.Icon {
	ic, err := widget.NewIcon(data)
	if err != nil {
		panic(err)
	}
	return ic
}

func newUI(w *app.Window) *ui {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))
	th.Palette.Fg = colText
	th.Palette.Bg = colCard
	th.Palette.ContrastBg = colAccent
	th.Palette.ContrastFg = colWhite
	th.TextSize = 15
	u := &ui{
		w:        w,
		th:       th,
		inbox:    make(chan func(), 64),
		sizes:    map[string]*sizeInfo{},
		icInit:   mustIcon(icons.ContentAddCircle),
		icUnlock: mustIcon(icons.ActionLockOpen),
		icLock:   mustIcon(icons.ActionLock),
		icReset:  mustIcon(icons.ActionDeleteForever),
		sizeBtns: make([]widget.Clickable, len(sizeChoices)+1),
	}
	u.scroll.Axis = layout.Vertical
	u.vList.Axis = layout.Horizontal
	for _, e := range []*widget.Editor{&u.edName, &u.edOwner, &u.edCustom, &u.edPw1, &u.edPw2, &u.edPw} {
		e.SingleLine = true
	}
	for _, e := range []*widget.Editor{&u.edPw1, &u.edPw2, &u.edPw} {
		e.Mask = '•'
		e.InputHint = key.HintPassword
	}
	u.edCustom.Filter = "0123456789"
	u.edCustom.MaxLen = 7
	u.edName.MaxLen = 200
	u.edOwner.MaxLen = 100
	return u
}

// post runs f on the UI goroutine at the next frame.
func (u *ui) post(f func()) {
	u.inbox <- f
	u.w.Invalidate()
}

// loop is the window's event loop. It never blocks on vault work.
func (u *ui) loop() {
	var ops op.Ops
	for {
		switch e := u.w.Event().(type) {
		case app.DestroyEvent:
			return
		case app.FrameEvent:
			u.drain()
			gtx := app.NewContext(&ops, e)
			u.update(gtx)
			u.layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

func (u *ui) drain() {
	for {
		select {
		case f := <-u.inbox:
			f()
		default:
			return
		}
	}
}

// ---- Background work ----

// goWork runs f in a goroutine tracked by u.ops; a panic becomes an error banner.
func (u *ui) goWork(f func()) {
	u.ops.Add(1)
	go func() {
		defer u.ops.Done()
		defer func() {
			if r := recover(); r != nil {
				u.post(func() {
					u.busy = false
					u.mode = modeHome
					u.setBanner(bannerError, fmt.Sprintf("Unexpected error: %v", r))
					u.refresh()
				})
			}
		}()
		f()
	}()
}

// refresh rediscovers the vaults in the background.
func (u *ui) refresh() {
	u.loading = true
	u.goWork(func() {
		found, err := discoverVaults(searchDirs())
		entries := make([]vaultEntry, len(found))
		for i, vi := range found {
			entries[i].info = vi
			v, oerr := vault.Open(vi.Path)
			if oerr != nil {
				entries[i].err = oerr
				continue
			}
			entries[i].label = v.Label()
			entries[i].capacity = v.Capacity()
		}
		u.post(func() {
			u.loading = false
			if err != nil {
				u.fatal = err.Error()
				return
			}
			prev := ""
			if c := u.current(); c != nil {
				prev = c.info.Path
			}
			u.vaults = entries
			u.vChips = make([]widget.Clickable, len(entries))
			u.sel = 0
			for i := range entries {
				if entries[i].info.Path == prev {
					u.sel = i
				}
			}
			u.sizes = map[string]*sizeInfo{}
		})
	})
}

func (u *ui) current() *vaultEntry {
	if u.sel >= 0 && u.sel < len(u.vaults) {
		return &u.vaults[u.sel]
	}
	return nil
}

// folderSizeOf returns the cached size of folder, starting a walk if needed.
func (u *ui) folderSizeOf(folder string) *sizeInfo {
	if s, ok := u.sizes[folder]; ok {
		return s
	}
	s := &sizeInfo{}
	u.sizes[folder] = s
	go func() {
		n := folderSize(folder)
		u.post(func() { s.bytes, s.done = n, true })
	}()
	return s
}

func (u *ui) progress(verifyText string) vault.Progress {
	u.progDone.Store(0)
	u.progTotal.Store(0)
	u.progPermil.Store(-1)
	u.verifyText = verifyText
	return func(done, total int64) {
		u.progDone.Store(done)
		u.progTotal.Store(total)
		if total > 0 {
			p := done * 1000 / total
			if u.progPermil.Swap(p) != p {
				u.w.Invalidate()
			}
		}
	}
}

func (u *ui) setBanner(k bannerKind, msg string) {
	u.bannerKind, u.bannerText = k, msg
}

// finish ends a long operation: shows the outcome and rediscovers vaults.
func (u *ui) finish(k bannerKind, msg string) {
	u.busy = false
	u.mode = modeHome
	u.setBanner(k, msg)
	u.refresh()
}

// ---- Allowed actions ----

func (u *ui) allowed() map[string]bool {
	m := map[string]bool{}
	if u.busy || u.loading || u.fatal != "" {
		return m
	}
	var vi *vaultInfo
	if c := u.current(); c != nil {
		vi = &c.info
	}
	for _, a := range allowedActions(vi) {
		m[a] = true
	}
	return m
}

// ---- Opening forms ----

func clearEditors(eds ...*widget.Editor) {
	for _, e := range eds {
		e.SetText("")
	}
}

func (u *ui) scrollTop() { u.scroll.Position = layout.Position{} }

func (u *ui) openInit(dir, name, owner string) {
	u.scrollTop()
	u.mode = modeInit
	u.formErr = ""
	u.initDir = dir
	u.edName.SetText(name)
	u.edOwner.SetText(owner)
	clearEditors(&u.edCustom, &u.edPw1, &u.edPw2)
	u.sizeSel = 0
	u.freeText = ""
	if free, err := freeSpace(dir); err == nil {
		u.freeText = fmt.Sprintf("%.1f GB free on the drive", float64(free)/float64(gib))
	}
	if name == "" {
		u.focus = &u.edName
	} else {
		u.focus = &u.edOwner
	}
}

func (u *ui) openPassword(m mode, vi vaultInfo) {
	u.scrollTop()
	u.mode = m
	u.target = vi
	u.formErr = ""
	clearEditors(&u.edPw)
	u.focus = &u.edPw
}

func (u *ui) cancelForm() {
	if u.pendingPw != nil {
		zero(u.pendingPw)
		u.pendingPw = nil
	}
	clearEditors(&u.edPw, &u.edPw1, &u.edPw2)
	u.scrollTop()
	u.mode = modeHome
	u.formErr = ""
}

// ---- Submitting ----

func (u *ui) submitForm() {
	switch u.mode {
	case modeInit:
		u.submitInit()
	case modeUnlock:
		u.submitUnlock()
	case modeLock:
		u.submitLock()
	}
}

func (u *ui) submitInit() {
	dir := u.initDir
	name, msg := checkName(dir, u.edName.Text())
	if msg != "" {
		u.formErr, u.focus = msg, &u.edName
		return
	}
	owner, msg := checkOwner(u.edOwner.Text())
	if msg != "" {
		u.formErr, u.focus = msg, &u.edOwner
		return
	}
	var gb int64
	if u.sizeSel < len(sizeChoices) {
		gb = sizeChoices[u.sizeSel]
	} else if gb, msg = parseGB(u.edCustom.Text()); msg != "" {
		u.formErr, u.focus = msg, &u.edCustom
		return
	}
	if msg := checkFree(dir, gb); msg != "" {
		u.formErr = msg
		return
	}
	if msg := checkNewPassword(u.edPw1.Text(), u.edPw2.Text()); msg != "" {
		u.formErr, u.focus = msg, &u.edPw1
		clearEditors(&u.edPw1, &u.edPw2)
		return
	}
	pw := []byte(u.edPw1.Text())
	clearEditors(&u.edPw1, &u.edPw2)
	u.formErr = ""
	u.startBusy("Creating…", "")
	prog := u.progress("")
	u.goWork(func() {
		msg, err := doCreate(dir, name, gb, owner, pw, prog)
		u.post(func() {
			if err != nil {
				u.finish(bannerError, friendly(err))
				return
			}
			u.finish(bannerOK, msg)
		})
	})
}

func (u *ui) startBusy(text, verify string) {
	u.busy = true
	u.busyText = text
	u.verifyText = verify
	u.setBanner(bannerNone, "")
}

func (u *ui) submitUnlock() {
	if u.edPw.Len() == 0 {
		u.formErr = "Enter the password."
		return
	}
	pw := []byte(u.edPw.Text())
	clearEditors(&u.edPw)
	vi := u.target
	u.formErr = ""
	u.startBusy("Decrypting…", "")
	prog := u.progress("")
	u.goWork(func() {
		msg, err := doUnlock(vi, pw, prog)
		u.post(func() {
			switch {
			case err == nil:
				u.finish(bannerOK, msg)
			case isWrongPassword(err):
				u.busy = false
				u.openPassword(modeUnlock, vi)
				u.formErr = friendly(err)
			default:
				u.finish(bannerError, friendly(err))
			}
		})
	})
}

func (u *ui) submitLock() {
	if u.edPw.Len() == 0 {
		u.formErr = "Enter the password."
		return
	}
	pw := []byte(u.edPw.Text())
	clearEditors(&u.edPw)
	vi := u.target
	u.formErr = ""
	u.startBusy("Checking password…", "")
	u.progress("")
	u.goWork(func() {
		ok, err := doCheckSession(vi, clone(pw))
		u.post(func() {
			switch {
			case err != nil && isWrongPassword(err):
				zero(pw)
				u.busy = false
				u.openPassword(modeLock, vi)
				u.formErr = friendly(err)
			case err != nil:
				zero(pw)
				u.finish(bannerError, friendly(err))
			case !ok:
				u.busy = false
				u.mode = modeLockConfirm
				u.pendingPw = pw
			default:
				u.runLock(vi, pw)
			}
		})
	})
}

// runLock starts the Lock itself; pw is zeroed when it is done.
func (u *ui) runLock(vi vaultInfo, pw []byte) {
	u.startBusy("Encrypting…", "Verifying…")
	prog := u.progress("Verifying…")
	u.goWork(func() {
		msg, notice, err := doLock(vi, pw, prog)
		u.post(func() {
			switch {
			case err != nil:
				u.finish(bannerError, friendly(err))
			case notice:
				u.finish(bannerNotice, msg)
			default:
				u.finish(bannerOK, msg)
			}
		})
	})
}

func (u *ui) runReset() {
	vi := u.target
	owner := u.targetOwner
	del := u.delFolder.Value && vi.FolderExists
	u.startBusy("Destroying the vault…", "")
	u.progress("")
	u.goWork(func() {
		warning, err := doReset(vi, del)
		u.post(func() {
			u.busy = false
			if err != nil {
				u.finish(bannerError, friendly(err))
				return
			}
			u.mode = modeHome
			if warning != "" {
				u.setBanner(bannerError, warning)
			} else {
				u.setBanner(bannerOK, fmt.Sprintf("Vault \"%s\" was destroyed. Create a new one below.", vi.Name))
			}
			u.refresh()
			u.openInit(vi.Dir, vi.Name, owner)
		})
	})
}

func isWrongPassword(err error) bool {
	return errors.Is(err, vault.ErrWrongPassword)
}

// ---- Event handling ----

func (u *ui) inInputForm() bool {
	return !u.busy && (u.mode == modeInit || u.mode == modeUnlock || u.mode == modeLock)
}

func (u *ui) update(gtx C) {
	// Keyboard: Esc cancels, Enter submits (unless a button has focus, in
	// which case Enter presses that button).
	filters := []event.Filter{key.Filter{Name: key.NameEscape}}
	if u.inInputForm() && !gtx.Focused(&u.cancel) && !gtx.Focused(&u.submit) {
		filters = append(filters, key.Filter{Name: key.NameReturn}, key.Filter{Name: key.NameEnter})
	}
	for {
		ev, ok := gtx.Event(filters...)
		if !ok {
			break
		}
		ke, ok := ev.(key.Event)
		if !ok || ke.State != key.Press {
			continue
		}
		switch ke.Name {
		case key.NameEscape:
			if !u.busy && u.mode != modeHome {
				u.cancelForm()
			}
		case key.NameReturn, key.NameEnter:
			u.submitForm()
		}
	}

	if u.bannerClose.Clicked(gtx) {
		u.setBanner(bannerNone, "")
	}
	for i := range u.vChips {
		if u.vChips[i].Clicked(gtx) && !u.busy && i != u.sel {
			u.sel = i
			if u.mode != modeInit {
				u.cancelForm()
			}
		}
	}

	allowed := u.allowed()
	if u.btnInit.Clicked(gtx) && allowed[actInitialize] {
		u.setBanner(bannerNone, "")
		u.openInit(newVaultDir(), "", "")
	}
	if c := u.current(); c != nil {
		if u.btnUnlock.Clicked(gtx) && allowed[actUnlock] {
			u.setBanner(bannerNone, "")
			u.cancelForm()
			u.openPassword(modeUnlock, c.info)
		}
		if u.btnLock.Clicked(gtx) && allowed[actLock] {
			u.setBanner(bannerNone, "")
			u.cancelForm()
			u.openPassword(modeLock, c.info)
		}
		if u.btnReset.Clicked(gtx) && allowed[actReset] {
			u.setBanner(bannerNone, "")
			u.cancelForm()
			u.mode = modeReset1
			u.target = c.info
			u.targetOwner = c.label.Owner
			u.delFolder.Value = false
		}
	}

	if u.busy {
		return
	}
	for i := range u.sizeBtns {
		if u.sizeBtns[i].Clicked(gtx) {
			u.sizeSel = i
			if i == len(sizeChoices) {
				u.focus = &u.edCustom
			}
		}
	}
	if u.cancel.Clicked(gtx) {
		u.cancelForm()
	}
	if u.submit.Clicked(gtx) {
		switch u.mode {
		case modeInit, modeUnlock, modeLock:
			u.submitForm()
		case modeLockConfirm:
			pw := u.pendingPw
			u.pendingPw = nil
			u.runLock(u.target, pw)
		case modeReset1:
			u.mode = modeReset2
		case modeReset2:
			u.runReset()
		}
	}
	if u.focus != nil {
		gtx.Execute(key.FocusCmd{Tag: u.focus})
		u.focus = nil
	}
}

// ---- Layout ----

func (u *ui) layout(gtx C) D {
	paint.Fill(gtx.Ops, colBg)
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(u.layHeader),
			layout.Rigid(u.laySelector),
			layout.Rigid(u.layBanner),
			layout.Flexed(1, u.layMain),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(u.layActions),
		)
	})
}

func (u *ui) label(size unit.Sp, txt string, col color.NRGBA, bold bool) material.LabelStyle {
	l := material.Label(u.th, size, txt)
	l.Color = col
	if bold {
		l.Font.Weight = font.Bold
	}
	return l
}

func (u *ui) layHeader(gtx C) D {
	return layout.Inset{Bottom: unit.Dp(10)}.Layout(gtx, func(gtx C) D {
		return layout.Flex{Alignment: layout.Baseline}.Layout(gtx,
			layout.Rigid(u.label(22, appTitle, colAccent, true).Layout),
			layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
			layout.Flexed(1, u.label(13, "Encrypted folders on this drive", colMuted, false).Layout),
		)
	})
}

func (u *ui) laySelector(gtx C) D {
	if len(u.vaults) < 2 {
		return D{}
	}
	labels := vaultLabels(vaultInfos(u.vaults))
	return layout.Inset{Bottom: unit.Dp(10)}.Layout(gtx, func(gtx C) D {
		return u.vList.Layout(gtx, len(labels), func(gtx C, i int) D {
			return layout.Inset{Right: unit.Dp(6)}.Layout(gtx, func(gtx C) D {
				if u.busy {
					gtx = gtx.Disabled()
				}
				return u.chip(gtx, &u.vChips[i], labels[i], i == u.sel)
			})
		})
	})
}

func vaultInfos(vs []vaultEntry) []vaultInfo {
	out := make([]vaultInfo, len(vs))
	for i := range vs {
		out[i] = vs[i].info
	}
	return out
}

func (u *ui) layBanner(gtx C) D {
	if u.bannerKind == bannerNone || u.bannerText == "" {
		return D{}
	}
	bg, fg := colOKBg, colOKFg
	switch u.bannerKind {
	case bannerNotice:
		bg, fg = colNoticeBg, colNoticeFg
	case bannerError:
		bg, fg = colErrBg, colErrFg
	}
	return layout.Inset{Bottom: unit.Dp(10)}.Layout(gtx, func(gtx C) D {
		return panel(gtx, bg, fg, unit.Dp(10), func(gtx C) D {
			return layout.Flex{Alignment: layout.Start}.Layout(gtx,
				layout.Flexed(1, u.label(14, u.bannerText, fg, false).Layout),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(func(gtx C) D {
					return u.bannerClose.Layout(gtx, u.label(18, "×", fg, true).Layout)
				}),
			)
		})
	})
}

func (u *ui) layMain(gtx C) D {
	return material.List(u.th, &u.scroll).Layout(gtx, 1, func(gtx C, _ int) D {
		return layout.Inset{Right: unit.Dp(6), Bottom: unit.Dp(12)}.Layout(gtx, func(gtx C) D {
			return u.card(gtx, u.layContent)
		})
	})
}

func (u *ui) layContent(gtx C) D {
	switch {
	case u.fatal != "":
		return u.label(15, u.fatal, colErrFg, false).Layout(gtx)
	case u.busy:
		return u.layBusy(gtx)
	}
	switch u.mode {
	case modeInit:
		return u.layInitForm(gtx)
	case modeUnlock, modeLock:
		return u.layPasswordForm(gtx)
	case modeLockConfirm:
		return u.layConfirm(gtx, "Replace the vault's contents?",
			fmt.Sprintf("This folder was not produced by unlocking \"%s\". Locking will REPLACE whatever is currently stored in the vault with this folder's contents.", u.target.Name),
			"Replace vault contents", nil)
	case modeReset1:
		return u.layConfirm(gtx, "Reset \""+u.target.Name+"\"?",
			fmt.Sprintf("Reset destroys the vault \"%s\". Everything stored in it becomes permanently unrecoverable.", u.target.Name),
			"Continue", nil)
	case modeReset2:
		var extra layout.Widget
		if u.target.FolderExists {
			extra = func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(material.CheckBox(u.th, &u.delFolder, "Also delete the unlocked folder").Layout),
					layout.Rigid(u.label(13, fmt.Sprintf("%s still exists. If you keep it, its files stay on the drive unencrypted.", u.target.Folder), colMuted, false).Layout),
				)
			}
		}
		return u.layConfirm(gtx, "Are you really sure?", "This cannot be undone.", "Destroy vault", extra)
	}
	if u.loading && len(u.vaults) == 0 {
		return u.label(15, "Looking for vaults…", colMuted, false).Layout(gtx)
	}
	return u.layStatus(gtx)
}

func (u *ui) layBusy(gtx C) D {
	done, total := u.progDone.Load(), u.progTotal.Load()
	txt := u.busyText
	if u.verifyText != "" && total > 0 && done*2 >= total {
		txt = u.verifyText
	}
	var frac float32
	if total > 0 {
		frac = float32(float64(done) / float64(total))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(u.label(17, txt, colText, true).Layout),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		layout.Rigid(func(gtx C) D {
			pb := material.ProgressBar(u.th, frac)
			pb.Height = unit.Dp(8)
			return pb.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx C) D {
			s := "Please wait. Do not remove the drive."
			if total > 0 {
				s = fmt.Sprintf("%d%%  ·  %s", int(frac*100), s)
			}
			return u.label(13, s, colMuted, false).Layout(gtx)
		}),
	)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("2 Jan 2006, 15:04")
}

func fmtGB(n int64) string {
	if n%gib == 0 {
		return fmt.Sprintf("%d GB", n/gib)
	}
	return fmt.Sprintf("%.1f GB", float64(n)/float64(gib))
}

func fmtBytes(n int64) string {
	switch {
	case n >= gib:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(gib))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

func (u *ui) layStatus(gtx C) D {
	c := u.current()
	if c == nil {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(u.label(20, "No vault on this drive yet", colText, true).Layout),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(u.label(14, "Choose Initialize to create one. It will be created in:", colMuted, false).Layout),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(u.label(14, newVaultDir(), colText, false).Layout),
		)
	}
	state, badge := "Locked", colBadgeLocked
	switch {
	case c.info.FolderExists:
		state, badge = "Unlocked", colBadgeUnlocked
	case c.err == nil && c.label.LastLocked.IsZero():
		state, badge = "Empty", colBadgeEmpty
	}
	rows := []layout.FlexChild{
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, u.label(24, c.info.Name, colText, true).Layout),
				layout.Rigid(func(gtx C) D { return u.badge(gtx, state, badge) }),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
	}
	if c.err != nil {
		rows = append(rows, layout.Rigid(u.label(14, "This vault cannot be read: "+friendly(c.err), colErrFg, false).Layout))
	} else {
		owner := c.label.Owner
		if owner == "" {
			owner = "not set"
		}
		rows = append(rows,
			u.row("Owner", owner),
			u.row("Capacity", fmtGB(c.capacity)),
			u.row("Created", fmtTime(c.label.Created)),
			u.row("Last unlocked", fmtTime(c.label.LastUnlocked)),
			u.row("Last locked", fmtTime(c.label.LastLocked)),
		)
	}
	if c.info.FolderExists {
		size := "calculating…"
		if s := u.folderSizeOf(c.info.Folder); s.done {
			size = fmtBytes(s.bytes)
		}
		rows = append(rows, u.row("Folder", c.info.Folder), u.row("Folder size", size))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

func (u *ui) row(k, v string) layout.FlexChild {
	return layout.Rigid(func(gtx C) D {
		return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx C) D {
			return layout.Flex{}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					w := gtx.Dp(120)
					gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
					return u.label(14, k, colMuted, false).Layout(gtx)
				}),
				layout.Flexed(1, u.label(14, v, colText, false).Layout),
			)
		})
	})
}

func (u *ui) layInitForm(gtx C) D {
	children := []layout.FlexChild{
		layout.Rigid(u.label(19, "Create a new vault", colText, true).Layout),
		layout.Rigid(u.label(13, "in "+u.initDir, colMuted, false).Layout),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		u.field("Vault name", &u.edName, "e.g. Private"),
		u.field("Owner", &u.edOwner, "your name"),
		u.fieldRow("Size", func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(u.laySizeChips),
				layout.Rigid(func(gtx C) D {
					if u.freeText == "" {
						return D{}
					}
					return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, u.label(12, u.freeText+"; at least 64 MB must stay free.", colMuted, false).Layout)
				}),
			)
		}),
		u.fieldRow("Password", func(gtx C) D {
			return layout.Flex{}.Layout(gtx,
				layout.Flexed(1, func(gtx C) D { return u.editorBox(gtx, &u.edPw1, "at least 8 characters") }),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Flexed(1, func(gtx C) D { return u.editorBox(gtx, &u.edPw2, "repeat it") }),
			)
		}),
		u.layFormFooter("Create vault"),
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func (u *ui) laySizeChips(gtx C) D {
	ws := make([]layout.Widget, len(u.sizeBtns))
	for i := range u.sizeBtns {
		txt := "Custom"
		if i < len(sizeChoices) {
			txt = fmt.Sprintf("%d GB", sizeChoices[i])
		}
		ws[i] = func(gtx C) D { return u.chip(gtx, &u.sizeBtns[i], txt, u.sizeSel == i) }
	}
	if u.sizeSel == len(sizeChoices) {
		ws = append(ws, func(gtx C) D {
			gtx.Constraints.Max.X = gtx.Dp(130)
			return u.editorBox(gtx, &u.edCustom, "GB, e.g. 8")
		})
	}
	return flow(gtx, gtx.Dp(6), ws)
}

// flow lays out ws left to right, wrapping to a new line when the width runs out.
func flow(gtx C, gap int, ws []layout.Widget) D {
	maxW := gtx.Constraints.Max.X
	cgtx := gtx
	cgtx.Constraints.Min = image.Point{}
	x, y, lineH, width := 0, 0, 0, 0
	for _, w := range ws {
		m := op.Record(gtx.Ops)
		d := w(cgtx)
		call := m.Stop()
		if x > 0 && x+d.Size.X > maxW {
			x, y, lineH = 0, y+lineH+gap, 0
		}
		t := op.Offset(image.Pt(x, y)).Push(gtx.Ops)
		call.Add(gtx.Ops)
		t.Pop()
		x += d.Size.X + gap
		lineH = max(lineH, d.Size.Y)
		width = max(width, x-gap)
	}
	return D{Size: image.Pt(width, y+lineH)}
}

func (u *ui) layPasswordForm(gtx C) D {
	title, verb := "Unlock \""+u.target.Name+"\"", "Unlock"
	hint := "Decrypts the vault into " + u.target.Folder
	if u.mode == modeLock {
		title, verb = "Lock \""+u.target.Name+"\"", "Lock"
		hint = "Encrypts " + u.target.Folder + " into the vault, checks it, then removes the folder."
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(u.label(19, title, colText, true).Layout),
		layout.Rigid(u.label(13, hint, colMuted, false).Layout),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		u.field("Password", &u.edPw, "vault password"),
		u.layFormFooter(verb),
	)
}

func (u *ui) layConfirm(gtx C, title, body, okText string, extra layout.Widget) D {
	children := []layout.FlexChild{
		layout.Rigid(u.label(19, title, colNoticeFg, true).Layout),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(u.label(14, body, colText, false).Layout),
	}
	if extra != nil {
		children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout), layout.Rigid(extra))
	}
	children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		layout.Rigid(func(gtx C) D {
			return layout.Flex{}.Layout(gtx,
				layout.Rigid(u.button(&u.submit, okText, colReset)),
				layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
				layout.Rigid(u.button(&u.cancel, "Cancel", colChip)),
			)
		}))
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func (u *ui) layFormFooter(okText string) layout.FlexChild {
	return layout.Rigid(func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				if u.formErr == "" {
					return D{}
				}
				return layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(6)}.Layout(gtx, u.label(14, u.formErr, colReset, false).Layout)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(u.button(&u.submit, okText, colAccent)),
					layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
					layout.Rigid(u.button(&u.cancel, "Cancel", colChip)),
					layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
					layout.Flexed(1, u.label(12, "Enter to confirm, Esc to cancel", colMuted, false).Layout),
				)
			}),
		)
	})
}

// ---- Widgets ----

func (u *ui) fieldLabel(txt string) layout.Widget {
	return func(gtx C) D {
		w := gtx.Dp(100)
		gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
		return u.label(14, txt, colText, false).Layout(gtx)
	}
}

func (u *ui) field(label string, ed *widget.Editor, hint string) layout.FlexChild {
	return u.fieldRow(label, func(gtx C) D { return u.editorBox(gtx, ed, hint) })
}

// fieldRow is a labelled form row.
func (u *ui) fieldRow(label string, w layout.Widget) layout.FlexChild {
	return layout.Rigid(func(gtx C) D {
		return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(u.fieldLabel(label)),
				layout.Flexed(1, w),
			)
		})
	})
}

func (u *ui) editorBox(gtx C, ed *widget.Editor, hint string) D {
	bc, bw := colBorder, unit.Dp(1)
	if gtx.Focused(ed) {
		bc, bw = colAccent, unit.Dp(2)
	}
	return widget.Border{Color: bc, CornerRadius: unit.Dp(6), Width: bw}.Layout(gtx, func(gtx C) D {
		return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(10), Right: unit.Dp(10)}.Layout(gtx, func(gtx C) D {
			e := material.Editor(u.th, ed, hint)
			e.TextSize = 15
			e.HintColor = colMuted
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return e.Layout(gtx)
		})
	})
}

func (u *ui) button(c *widget.Clickable, txt string, bg color.NRGBA) layout.Widget {
	return func(gtx C) D {
		b := material.Button(u.th, c, txt)
		b.Background = bg
		b.TextSize = 15
		b.CornerRadius = unit.Dp(8)
		if bg == colChip {
			b.Color = colText
		}
		return b.Layout(gtx)
	}
}

func (u *ui) chip(gtx C, c *widget.Clickable, txt string, selected bool) D {
	return c.Layout(gtx, func(gtx C) D {
		bg, fg := colChip, colText
		switch {
		case selected:
			bg, fg = colAccent, colWhite
		case c.Hovered() && gtx.Enabled():
			bg = colChipHover
		}
		return layout.Background{}.Layout(gtx,
			func(gtx C) D { return fillRRect(gtx, bg, unit.Dp(14)) },
			func(gtx C) D {
				return layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5), Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx,
					u.label(14, txt, fg, selected).Layout)
			})
	})
}

func (u *ui) badge(gtx C, txt string, bg color.NRGBA) D {
	return layout.Background{}.Layout(gtx,
		func(gtx C) D { return fillRRect(gtx, bg, unit.Dp(12)) },
		func(gtx C) D {
			return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx,
				u.label(13, txt, colWhite, true).Layout)
		})
}

func (u *ui) card(gtx C, w layout.Widget) D {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return panel(gtx, colCard, colBorder, unit.Dp(18), w)
}

// panel draws w on a rounded rectangle with a 1dp border.
func panel(gtx C, bg, border color.NRGBA, pad unit.Dp, w layout.Widget) D {
	return widget.Border{Color: border, CornerRadius: unit.Dp(10), Width: unit.Dp(1)}.Layout(gtx, func(gtx C) D {
		return layout.Background{}.Layout(gtx,
			func(gtx C) D { return fillRRect(gtx, bg, unit.Dp(10)) },
			func(gtx C) D {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return layout.UniformInset(pad).Layout(gtx, w)
			})
	})
}

func fillRRect(gtx C, c color.NRGBA, r unit.Dp) D {
	sz := gtx.Constraints.Min
	defer clip.UniformRRect(image.Rectangle{Max: sz}, gtx.Dp(r)).Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, c)
	return D{Size: sz}
}

func (u *ui) layActions(gtx C) D {
	allowed := u.allowed()
	type act struct {
		btn  *widget.Clickable
		ic   *widget.Icon
		name string
		col  color.NRGBA
	}
	acts := []act{
		{&u.btnInit, u.icInit, actInitialize, colInit},
		{&u.btnUnlock, u.icUnlock, actUnlock, colUnlock},
		{&u.btnLock, u.icLock, actLock, colLock},
		{&u.btnReset, u.icReset, actReset, colReset},
	}
	children := make([]layout.FlexChild, 0, 2*len(acts))
	for i, a := range acts {
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout))
		}
		children = append(children, layout.Flexed(1, func(gtx C) D {
			return u.actionButton(gtx, a.btn, a.ic, a.name, a.col, allowed[a.name])
		}))
	}
	return layout.Flex{}.Layout(gtx, children...)
}

func (u *ui) actionButton(gtx C, b *widget.Clickable, ic *widget.Icon, caption string, bg color.NRGBA, enabled bool) D {
	fg := colWhite
	if !enabled {
		gtx = gtx.Disabled()
		bg = rgb(0xc9ced6)
		fg = rgb(0xf4f5f7)
	}
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return material.ButtonLayoutStyle{Background: bg, CornerRadius: unit.Dp(12), Button: b}.Layout(gtx, func(gtx C) D {
		return layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(8), Left: unit.Dp(6), Right: unit.Dp(6)}.Layout(gtx, func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx C) D {
					gtx.Constraints.Min.X = gtx.Dp(32)
					return ic.Layout(gtx, fg)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
				layout.Rigid(u.label(14, caption, fg, true).Layout),
			)
		})
	})
}
