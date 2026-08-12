// Command tpm-fido-tray is a small GTK3 window for managing a running
// tpm-fido daemon: view/delete resident credentials per site, and
// set/change the CTAP2 PIN. It talks to the daemon over the local control
// socket (see the ctlsocket package) -- it never touches the TPM, HID
// device, or on-disk stores directly.
package main

import (
	"fmt"
	"log"

	"github.com/gotk3/gotk3/gtk"
	"github.com/psanford/tpm-fido/ctlsocket"
)

func main() {
	gtk.Init(nil)

	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		log.Fatalf("create window: %s", err)
	}
	win.SetTitle("tpm-fido")
	win.SetDefaultSize(480, 420)
	win.Connect("destroy", func() {
		gtk.MainQuit()
	})

	app := newApp(win)
	win.Add(app.root)

	if err := app.refresh(); err != nil {
		app.showError(fmt.Sprintf("Could not connect to tpm-fido: %s\n\nIs the tpm-fido service running?", err))
	}

	win.ShowAll()
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
