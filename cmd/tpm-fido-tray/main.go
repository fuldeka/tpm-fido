// Command tpm-fido-tray is a system tray icon for managing a running
// tpm-fido daemon: view/delete resident credentials per site, and
// set/change the CTAP2 PIN, via a GTK3 window opened from the tray menu.
// It talks to the daemon over the local control socket (see the ctlsocket
// package) -- it never touches the TPM, HID device, or on-disk stores
// directly.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"

	"github.com/getlantern/systray"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"github.com/psanford/tpm-fido/ctlsocket"
)

//go:embed icon/icon.png
var iconPNG []byte

func main() {
	systray.Run(onTrayReady, onTrayExit)
}

func onTrayReady() {
	systray.SetIcon(iconPNG)
	systray.SetTitle("tpm-fido")
	systray.SetTooltip("tpm-fido: manage PIN and credentials")

	openItem := systray.AddMenuItem("Open tpm-fido Manager", "View PIN status, Windows Hello mode, and credentials")
	systray.AddSeparator()
	quitItem := systray.AddMenuItem("Quit", "Quit tpm-fido-tray")

	// GTK owns its own event loop (gtk.Main) once initialized, but that
	// only needs to happen on some goroutine -- unlike systray, which
	// locks the actual process main thread on init, gotk3's GTK binding
	// doesn't require being on that specific thread, only being
	// self-consistent about which thread it runs its own loop on. Doing
	// GTK setup lazily here (rather than in main) keeps the tray icon
	// responsive even before the window is ever opened.
	go runGTK(openItem, quitItem)
}

func onTrayExit() {}

func runGTK(openItem, quitItem *systray.MenuItem) {
	gtk.Init(nil)

	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		log.Fatalf("create window: %s", err)
	}
	win.SetTitle("tpm-fido")
	win.SetDefaultSize(480, 420)
	// Closing the window (the 'x' button) hides it rather than exiting
	// the process -- the tray icon and daemon connection stay alive, same
	// as any other tray-managed app. Quit is only reachable via the tray
	// menu's explicit Quit item.
	win.Connect("delete-event", func() bool {
		win.Hide()
		return true
	})

	app := newApp(win)
	win.Add(app.root)

	go func() {
		for {
			select {
			case <-openItem.ClickedCh:
				glib.IdleAdd(func() {
					if err := app.refresh(); err != nil {
						app.showError(fmt.Sprintf("Could not connect to tpm-fido: %s\n\nIs the tpm-fido service running?", err))
					}
					win.ShowAll()
					win.Present()
				})
			case <-quitItem.ClickedCh:
				systray.Quit()
				glib.IdleAdd(gtk.MainQuit)
				return
			}
		}
	}()

	gtk.Main()
}

// call is a thin wrapper around ctlsocket.Call using the default socket
// path, with the result type parameter decoded via the caller.
func call(method string, params interface{}) (*ctlsocket.Response, error) {
	resp, err := ctlsocket.Call("", method, params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// getInternalUV reads the daemon's persisted "Windows Hello mode" toggle.
func getInternalUV() (bool, error) {
	resp, err := call("GetInternalUV", nil)
	if err != nil {
		return false, err
	}
	var r struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return false, err
	}
	return r.Enabled, nil
}

// setInternalUV writes the toggle and returns the value the daemon stored.
func setInternalUV(enabled bool) (bool, error) {
	resp, err := call("SetInternalUV", map[string]bool{"enabled": enabled})
	if err != nil {
		return false, err
	}
	var r struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return false, err
	}
	return r.Enabled, nil
}
