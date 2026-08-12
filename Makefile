PREFIX ?= $(HOME)/.local
BINDIR := $(PREFIX)/bin
APPDIR := $(HOME)/.local/share/applications
AUTOSTARTDIR := $(HOME)/.config/autostart
ICONSRC := cmd/tpm-fido-tray/icon/icon.png

.PHONY: build install uninstall clean

build:
	go build -o tpm-fido .
	go build -o tpm-fido-tray ./cmd/tpm-fido-tray

install: build
	install -Dm755 tpm-fido "$(BINDIR)/tpm-fido"
	install -Dm755 tpm-fido-tray "$(BINDIR)/tpm-fido-tray"
	install -Dm644 $(ICONSRC) "$(PREFIX)/share/icons/tpm-fido.png"
	@mkdir -p "$(APPDIR)" "$(AUTOSTARTDIR)"
	@sed \
		-e 's|@BINDIR@|$(BINDIR)|g' \
		-e 's|@ICON@|$(PREFIX)/share/icons/tpm-fido.png|g' \
		packaging/tpm-fido.desktop.in > "$(AUTOSTARTDIR)/tpm-fido.desktop"
	@sed \
		-e 's|@BINDIR@|$(BINDIR)|g' \
		-e 's|@ICON@|$(PREFIX)/share/icons/tpm-fido.png|g' \
		packaging/tpm-fido-tray.desktop.in > "$(APPDIR)/tpm-fido-tray.desktop"
	@echo "Installed. Log out and back in (or run 'tpm-fido &' manually) to start the daemon."
	@echo "Make sure $(BINDIR) is on your PATH."

uninstall:
	rm -f "$(BINDIR)/tpm-fido" "$(BINDIR)/tpm-fido-tray"
	rm -f "$(PREFIX)/share/icons/tpm-fido.png"
	rm -f "$(AUTOSTARTDIR)/tpm-fido.desktop"
	rm -f "$(APPDIR)/tpm-fido-tray.desktop"

clean:
	rm -f tpm-fido tpm-fido-tray
