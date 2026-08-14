# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

##  Implementation details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## CTAP2 / resident (discoverable) credentials

tpm-fido also implements a subset of CTAP2 over the same HID transport: `authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorClientPIN` (PIN/UV Auth Protocol One: getKeyAgreement, setPIN, changePIN, getPINToken, getPinUvAuthTokenUsingUvWithPermissions, getPINRetries, getUVRetries), and a read/delete subset of `authenticatorCredentialManagement` (getCredsMetadata, enumerateRPs, enumerateCredentials, deleteCredential). This is what lets tpm-fido register as a **resident/discoverable key** ("passkey") with PIN-based user verification, which sites like GitHub require — the original U2F-only implementation cannot satisfy that requirement, since resident keys and PIN-based UV are CTAP2-only concepts with no equivalent in the U2F protocol.

Discoverable credential metadata (rpId, user id/name, credential id, a per-credential sign counter) is persisted to `$XDG_CONFIG_HOME/tpm-fido/resident-credentials.json` (override with `-resident-store <path>`). The PIN's hash and retry counter are persisted to `$XDG_CONFIG_HOME/tpm-fido/pin-state.json` (override with `-pin-store <path>`) — the PIN itself is never stored, only left-16-bytes-of-SHA-256(PIN). Only metadata needed to locate and re-derive a credential is stored there; the private key material stays TPM-sealed inside the credential's own key handle exactly as in the U2F flow, so a leaked store file alone does not expose signing keys when using the `tpm` backend.

### Windows Hello mode (internal user verification)

By default, tpm-fido advertises CTAP 2.1 built-in user verification (`uv:true` + `pinUvAuthToken`, alongside `FIDO_2_1`) whenever a PIN is set. In this mode the browser shows **no PIN box**: it drives `getPinUvAuthTokenUsingUvWithPermissions` and tpm-fido collects the PIN in its own `pinentry` system dialog, verifying it against the same `pin-state.json` hash used by the browser-collected PIN path. This is the Windows-Hello / Touch-ID interaction model — the PIN prompt belongs to the authenticator, not the web page. Credentials are mode-agnostic: one registered while this mode was off (browser-collected PIN) authenticates unchanged while it's on, and vice versa.

The mode is a persisted, per-user toggle (`$XDG_CONFIG_HOME/tpm-fido/uv-config.json`, override with `-uv-config <path>`), **on by default**, flipped live from the "Windows Hello mode" switch in the `tpm-fido-tray` manager window — no restart needed. Turn it off to fall back to plain clientPIN behaviour (the browser collects the PIN) if a browser update ever regresses internal UV over HID. The built-in UV backend is PIN-based today, but is structured behind an interface so a biometric backend could replace it without touching the CTAP2 layer.

Non-resident (classic allowList-based) WebAuthn and legacy U2F both continue to work unchanged and require no local state.

CTAPHID_CANCEL is supported: canceling an in-progress registration/authentication from the browser (e.g. clicking "Cancel" on the PIN/presence prompt) properly aborts the pending pinentry prompt and request, rather than leaving it dangling.

Known limitations of the CTAP2 support:
- If multiple accounts are registered as resident credentials for the same site, `authenticatorGetAssertion` always uses the most recently created one rather than surfacing an account picker.
- Credential management enumeration/deletion works over CTAP2 (e.g. via `fido2-token -L -r` / `-D`, or a browser's own passkey manager where supported), and additionally via the `tpm-fido-tray` companion app described below.

## tpm-fido-tray

`tpm-fido-tray` is an optional companion GUI: a system tray icon that opens a manager window for setting/changing the PIN, toggling Windows Hello mode, viewing/deleting resident credentials, and clearing a PIN lockout (an "Unlock" button shown only while locked out), without needing a CLI tool or relying on a browser's own (often absent) PIN-setup UI. It talks to the running `tpm-fido` daemon over a local Unix control socket (`$XDG_RUNTIME_DIR/tpm-fido.sock` by default) — it never touches the TPM, HID device, or on-disk stores directly.

If `tpm-fido-tray` is found on `$PATH`, the `tpm-fido` daemon launches it automatically once its control socket is ready (pass `-no-tray` to disable this). It can also be launched manually or from an application menu.

Requires GTK3 and `libayatana-appindicator3` (or `libappindicator3`) at build and run time — see Dependencies below.

## Status

tpm-fido has been tested to work with Chrome and Firefox on Linux, including CTAP2 resident-key registration/authentication with PIN-based user verification against webauthn.io and GitHub, in both the default Windows Hello mode (authenticator-side PIN prompt) and the browser-collected clientPIN fallback — including that credentials registered in one mode authenticate in the other.

## Installation

```
git clone https://github.com/idkreally001/tpm-fido
cd tpm-fido
make install
```

This builds both `tpm-fido` and `tpm-fido-tray` and installs them to `~/.local/bin`, along with a `.desktop` entry so `tpm-fido` starts automatically on login (`~/.config/autostart/tpm-fido.desktop`) and an application-menu entry for `tpm-fido-tray` (`~/.local/share/applications/tpm-fido-tray.desktop`). Make sure `~/.local/bin` is on your `$PATH`.

To remove everything the installer added:
```
make uninstall
```

To just build the binaries without installing anything system-wide:
```
make build
```

## Running

In order to run `tpm-fido` you will need permission to access `/dev/tpmrm0`. On Ubuntu and Arch, you can add your user to the `tss` group.

Your user also needs permission to access `/dev/uhid` so that `tpm-fido` can appear to be a USB device.
I use the following udev rule to set the appropriate `uhid` permissions:

```
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="SOME_UHID_GROUP_MY_USER_BELONGS_TO", MODE="0660"
```

To ensure the above udev rule gets triggered, I also add the `uhid` module to `/etc/modules-load.d/uhid.conf` so that it loads at boot.

To run (after `make install`, or from `./tpm-fido` in the repo root after `make build`):

```
# as a user that has permission to read and write to /dev/tpmrm0:
tpm-fido
```
Note: do not run with `sudo` or as root, as it will not work.

## Dependencies

- `pinentry` must be available on the system for presence/PIN confirmation prompts. If you have gpg installed you most likely already have `pinentry`.
- Building/running `tpm-fido-tray` additionally requires GTK3 (`gtk3` / `libgtk-3-dev`) and an AppIndicator library (`libayatana-appindicator` on modern distros, or `libappindicator3` on older ones) for the system tray icon. `tpm-fido` itself has no GUI dependency beyond `pinentry`.
