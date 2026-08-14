package main

import (
	"encoding/json"
	"fmt"

	"github.com/gotk3/gotk3/gtk"
)

// credentialInfo mirrors the daemon's ctlapi.CredentialInfo JSON shape.
// Duplicated here rather than imported from the main package, since main
// package types aren't importable and pulling in the whole daemon just for
// this struct isn't worth it.
type credentialInfo struct {
	CredentialID string `json:"credential_id"`
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	SignCount    uint32 `json:"sign_count"`
}

type pinStatus struct {
	IsSet       bool `json:"is_set"`
	RetriesLeft int  `json:"retries_left"`
}

type app struct {
	win  *gtk.Window
	root *gtk.Box

	statusLabel  *gtk.Label
	pinButton    *gtk.Button
	unlockButton *gtk.Button
	helloSwitch  *gtk.Switch
	rpList       *gtk.ListBox
	credList    *gtk.ListBox
	deleteBtn   *gtk.Button

	rpIDs        []string
	selectedRPID string
	creds        []credentialInfo
	selectedCred string // base64 credential_id

	// suppressHelloSignal is set while programmatically syncing helloSwitch
	// so refresh-driven SetActive doesn't re-fire onHelloSwitchToggled and
	// bounce a redundant write back to the daemon.
	suppressHelloSignal bool
}

func newApp(win *gtk.Window) *app {
	a := &app{win: win}

	root, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 8)
	root.SetMarginTop(12)
	root.SetMarginBottom(12)
	root.SetMarginStart(12)
	root.SetMarginEnd(12)
	a.root = root

	// PIN status row.
	pinRow, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 8)
	a.statusLabel, _ = gtk.LabelNew("PIN status: checking...")
	a.statusLabel.SetHAlign(gtk.ALIGN_START)
	// Unlock button: only shown when the PIN is locked out (retries==0), as a
	// non-destructive recovery path (resets the retry counter, keeps PIN and
	// credentials). Hidden otherwise to avoid clutter.
	a.unlockButton, _ = gtk.ButtonNewWithLabel("Unlock")
	a.unlockButton.SetTooltipText("Clear the failed-attempt lockout without changing your PIN or credentials")
	// Keep gtk.Widget.ShowAll (called when the window opens) from forcing the
	// Unlock button visible; its visibility is driven solely by lock state in
	// refreshPINStatus.
	a.unlockButton.SetNoShowAll(true)
	a.unlockButton.Connect("clicked", a.onUnlockClicked)
	a.pinButton, _ = gtk.ButtonNewWithLabel("Set PIN")
	a.pinButton.Connect("clicked", a.onPINButtonClicked)
	pinRow.PackStart(a.statusLabel, true, true, 0)
	pinRow.PackStart(a.unlockButton, false, false, 0)
	pinRow.PackStart(a.pinButton, false, false, 0)
	root.PackStart(pinRow, false, false, 0)

	// Windows Hello mode row: authenticator-side PIN prompt (no browser PIN
	// box) vs. plain browser-collected clientPIN.
	helloRow, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 8)
	helloLabel, _ := gtk.LabelNew("Windows Hello mode")
	helloLabel.SetHAlign(gtk.ALIGN_START)
	helloLabel.SetTooltipText("When on, tpm-fido asks for your PIN in its own dialog instead of the browser's PIN box")
	a.helloSwitch, _ = gtk.SwitchNew()
	a.helloSwitch.SetHAlign(gtk.ALIGN_END)
	a.helloSwitch.SetVAlign(gtk.ALIGN_CENTER)
	a.helloSwitch.Connect("state-set", a.onHelloSwitchToggled)
	helloRow.PackStart(helloLabel, true, true, 0)
	helloRow.PackStart(a.helloSwitch, false, false, 0)
	root.PackStart(helloRow, false, false, 0)

	sep, _ := gtk.SeparatorNew(gtk.ORIENTATION_HORIZONTAL)
	root.PackStart(sep, false, false, 4)

	// Main content: RP list on the left, credential list on the right.
	content, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 8)
	root.PackStart(content, true, true, 0)

	rpBox, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 4)
	rpLabel, _ := gtk.LabelNew("Sites")
	rpLabel.SetHAlign(gtk.ALIGN_START)
	rpBox.PackStart(rpLabel, false, false, 0)
	rpScroll, _ := gtk.ScrolledWindowNew(nil, nil)
	rpScroll.SetSizeRequest(180, -1)
	a.rpList, _ = gtk.ListBoxNew()
	a.rpList.Connect("row-selected", a.onRPSelected)
	rpScroll.Add(a.rpList)
	rpBox.PackStart(rpScroll, true, true, 0)
	content.PackStart(rpBox, false, false, 0)

	credBox, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 4)
	credLabel, _ := gtk.LabelNew("Credentials")
	credLabel.SetHAlign(gtk.ALIGN_START)
	credBox.PackStart(credLabel, false, false, 0)
	credScroll, _ := gtk.ScrolledWindowNew(nil, nil)
	a.credList, _ = gtk.ListBoxNew()
	a.credList.Connect("row-selected", a.onCredSelected)
	credScroll.Add(a.credList)
	credBox.PackStart(credScroll, true, true, 0)
	content.PackStart(credBox, true, true, 0)

	// Bottom action row.
	actionRow, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 8)
	actionRow.SetHAlign(gtk.ALIGN_END)
	refreshBtn, _ := gtk.ButtonNewWithLabel("Refresh")
	refreshBtn.Connect("clicked", func() { a.refresh() })
	a.deleteBtn, _ = gtk.ButtonNewWithLabel("Delete Credential")
	a.deleteBtn.SetSensitive(false)
	a.deleteBtn.Connect("clicked", a.onDeleteClicked)
	actionRow.PackStart(refreshBtn, false, false, 0)
	actionRow.PackStart(a.deleteBtn, false, false, 0)
	root.PackStart(actionRow, false, false, 0)

	return a
}

func (a *app) refresh() error {
	if err := a.refreshPINStatus(); err != nil {
		return err
	}
	a.refreshHelloSwitch()
	return a.refreshRPs()
}

func (a *app) refreshPINStatus() error {
	resp, err := call(methodPINStatus, nil)
	if err != nil {
		a.statusLabel.SetText("PIN status: unavailable")
		return err
	}
	var status pinStatus
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		return err
	}
	locked := status.IsSet && status.RetriesLeft <= 0
	if status.IsSet {
		if locked {
			a.statusLabel.SetText("PIN is LOCKED (too many wrong attempts)")
		} else {
			a.statusLabel.SetText(fmt.Sprintf("PIN is set (%d retries left)", status.RetriesLeft))
		}
		a.pinButton.SetLabel("Change PIN")
	} else {
		a.statusLabel.SetText("No PIN set")
		a.pinButton.SetLabel("Set PIN")
	}
	// Unlock is only relevant (and only offered) while locked out.
	a.unlockButton.SetVisible(locked)
	return nil
}

// refreshHelloSwitch syncs the switch to the daemon's persisted state without
// re-triggering onHelloSwitchToggled (guarded by suppressHelloSignal).
func (a *app) refreshHelloSwitch() {
	enabled, err := getInternalUV()
	if err != nil {
		// Leave the switch as-is; the daemon is unreachable.
		return
	}
	a.suppressHelloSignal = true
	a.helloSwitch.SetActive(enabled)
	a.suppressHelloSignal = false
}

func (a *app) refreshRPs() error {
	resp, err := call(methodListRPs, nil)
	if err != nil {
		return err
	}
	var rpIDs []string
	if err := json.Unmarshal(resp.Result, &rpIDs); err != nil {
		return err
	}
	a.rpIDs = rpIDs

	clearListBox(a.rpList)
	for _, rpID := range rpIDs {
		row, _ := gtk.LabelNew(rpID)
		row.SetHAlign(gtk.ALIGN_START)
		row.SetMarginStart(4)
		row.SetMarginEnd(4)
		a.rpList.Add(row)
	}
	a.rpList.ShowAll()

	clearListBox(a.credList)
	a.creds = nil
	a.selectedRPID = ""
	a.selectedCred = ""
	a.deleteBtn.SetSensitive(false)

	return nil
}

func (a *app) onRPSelected() {
	row := a.rpList.GetSelectedRow()
	if row == nil {
		return
	}
	idx := row.GetIndex()
	if idx < 0 || idx >= len(a.rpIDs) {
		return
	}
	a.selectedRPID = a.rpIDs[idx]
	a.refreshCreds()
}

func (a *app) refreshCreds() {
	if a.selectedRPID == "" {
		return
	}

	resp, err := call(methodListCreds, map[string]string{"rp_id": a.selectedRPID})
	if err != nil {
		a.showError(fmt.Sprintf("List credentials failed: %s", err))
		return
	}
	var creds []credentialInfo
	if err := json.Unmarshal(resp.Result, &creds); err != nil {
		a.showError(fmt.Sprintf("Parse credentials failed: %s", err))
		return
	}
	a.creds = creds

	clearListBox(a.credList)
	for _, c := range creds {
		label := c.UserName
		if label == "" {
			label = "(no username)"
		}
		row, _ := gtk.LabelNew(fmt.Sprintf("%s  [used %d times]", label, c.SignCount))
		row.SetHAlign(gtk.ALIGN_START)
		row.SetMarginStart(4)
		row.SetMarginEnd(4)
		a.credList.Add(row)
	}
	a.credList.ShowAll()
	a.selectedCred = ""
	a.deleteBtn.SetSensitive(false)
}

func (a *app) onCredSelected() {
	row := a.credList.GetSelectedRow()
	if row == nil {
		a.deleteBtn.SetSensitive(false)
		return
	}
	idx := row.GetIndex()
	if idx < 0 || idx >= len(a.creds) {
		return
	}
	a.selectedCred = a.creds[idx].CredentialID
	a.deleteBtn.SetSensitive(true)
}

func (a *app) onDeleteClicked() {
	if a.selectedRPID == "" || a.selectedCred == "" {
		return
	}

	confirm := gtk.MessageDialogNew(a.win, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION, gtk.BUTTONS_YES_NO,
		"Delete this credential for %s?\n\nThis cannot be undone from this side; the site will still show it as registered until you remove it there too.", a.selectedRPID)
	resp := confirm.Run()
	confirm.Destroy()
	if resp != gtk.RESPONSE_YES {
		return
	}

	_, err := call(methodDeleteCred, map[string]string{
		"rp_id":         a.selectedRPID,
		"credential_id": a.selectedCred,
	})
	if err != nil {
		a.showError(fmt.Sprintf("Delete failed: %s", err))
		return
	}

	a.refreshRPs()
}

// onHelloSwitchToggled writes the new Windows Hello mode state to the daemon.
// Returning false lets GTK apply the visual state change. On failure it
// reconciles the switch back to the daemon's actual state.
func (a *app) onHelloSwitchToggled(_ *gtk.Switch, state bool) bool {
	if a.suppressHelloSignal {
		return false
	}
	if _, err := setInternalUV(state); err != nil {
		a.showError(fmt.Sprintf("Could not change Windows Hello mode: %s", err))
		a.refreshHelloSwitch()
	}
	return false
}

// onUnlockClicked clears a PIN lockout after confirmation. Non-destructive:
// it resets the retry counter but keeps the PIN and all credentials.
func (a *app) onUnlockClicked() {
	confirm := gtk.MessageDialogNew(a.win, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION, gtk.BUTTONS_YES_NO,
		"Clear the PIN lockout?\n\nThis resets the failed-attempt counter so you can use your PIN again. Your PIN and credentials are kept unchanged. Only do this if you're sure the earlier failed attempts were your own.")
	resp := confirm.Run()
	confirm.Destroy()
	if resp != gtk.RESPONSE_YES {
		return
	}

	if _, err := call(methodResetPINRetries, nil); err != nil {
		a.showError(fmt.Sprintf("Unlock failed: %s", err))
		return
	}
	a.refreshPINStatus()
}

func (a *app) onPINButtonClicked() {
	resp, err := call(methodPINStatus, nil)
	if err != nil {
		a.showError(fmt.Sprintf("Could not check PIN status: %s", err))
		return
	}
	var status pinStatus
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		a.showError(err.Error())
		return
	}

	if status.IsSet {
		a.runChangePINDialog()
	} else {
		a.runSetPINDialog()
	}
}

func (a *app) runSetPINDialog() {
	dlg := gtk.MessageDialogNew(a.win, gtk.DIALOG_MODAL, gtk.MESSAGE_OTHER, gtk.BUTTONS_OK_CANCEL, "Set a new PIN")
	entry, _ := gtk.EntryNew()
	entry.SetVisibility(false)
	entry.SetPlaceholderText("New PIN (min 4 characters)")
	box, _ := dlg.GetContentArea()
	box.PackStart(entry, false, false, 8)
	dlg.ShowAll()

	resp := dlg.Run()
	pin, _ := entry.GetText()
	dlg.Destroy()

	if resp != gtk.RESPONSE_OK || pin == "" {
		return
	}

	if _, err := call(methodSetPIN, map[string]string{"new_pin": pin}); err != nil {
		a.showError(fmt.Sprintf("Set PIN failed: %s", err))
		return
	}
	a.refreshPINStatus()
}

func (a *app) runChangePINDialog() {
	dlg := gtk.MessageDialogNew(a.win, gtk.DIALOG_MODAL, gtk.MESSAGE_OTHER, gtk.BUTTONS_OK_CANCEL, "Change PIN")
	box, _ := dlg.GetContentArea()

	oldEntry, _ := gtk.EntryNew()
	oldEntry.SetVisibility(false)
	oldEntry.SetPlaceholderText("Current PIN")
	box.PackStart(oldEntry, false, false, 4)

	newEntry, _ := gtk.EntryNew()
	newEntry.SetVisibility(false)
	newEntry.SetPlaceholderText("New PIN (min 4 characters)")
	box.PackStart(newEntry, false, false, 4)

	dlg.ShowAll()
	resp := dlg.Run()
	oldPin, _ := oldEntry.GetText()
	newPin, _ := newEntry.GetText()
	dlg.Destroy()

	if resp != gtk.RESPONSE_OK || oldPin == "" || newPin == "" {
		return
	}

	if _, err := call(methodChangePIN, map[string]string{"old_pin": oldPin, "new_pin": newPin}); err != nil {
		a.showError(fmt.Sprintf("Change PIN failed: %s", err))
		return
	}
	a.refreshPINStatus()
}

func (a *app) showError(msg string) {
	dlg := gtk.MessageDialogNew(a.win, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, "%s", msg)
	dlg.Run()
	dlg.Destroy()
}

func clearListBox(lb *gtk.ListBox) {
	children := lb.GetChildren()
	children.Foreach(func(item interface{}) {
		if w, ok := item.(interface{ Destroy() }); ok {
			w.Destroy()
		}
	})
}

const (
	methodListRPs    = "ListRPs"
	methodListCreds  = "ListCreds"
	methodDeleteCred = "DeleteCred"
	methodPINStatus  = "PINStatus"
	methodSetPIN     = "SetPIN"
	methodChangePIN  = "ChangePIN"

	methodResetPINRetries = "ResetPINRetries"
)
