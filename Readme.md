# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

##  Implementation details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## CTAP2 / resident (discoverable) credentials

tpm-fido also implements a subset of CTAP2 over the same HID transport: `authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`, and a read/delete subset of `authenticatorCredentialManagement` (getCredsMetadata, enumerateRPs, enumerateCredentials, deleteCredential). This is what lets tpm-fido register as a **resident/discoverable key** ("passkey"), which sites like GitHub require — the original U2F-only implementation cannot satisfy that requirement, since resident keys are a CTAP2-only concept with no equivalent in the U2F protocol.

Discoverable credential metadata (rpId, user id/name, credential id, a per-credential sign counter) is persisted to `$XDG_CONFIG_HOME/tpm-fido/resident-credentials.json` (override with `-resident-store <path>`). Only metadata needed to locate and re-derive a credential is stored there; the private key material stays TPM-sealed inside the credential's own key handle exactly as in the U2F flow, so a leaked store file alone does not expose signing keys when using the `tpm` backend.

Non-resident (classic allowList-based) WebAuthn and legacy U2F both continue to work unchanged and require no local state.

Known limitations of the CTAP2 support:
- No PIN protocol (`clientPin`) — user verification is satisfied via the same pinentry user-presence prompt used for U2F, not a PIN.
- If multiple accounts are registered as resident credentials for the same site, `authenticatorGetAssertion` always uses the most recently created one rather than surfacing an account picker.
- Credential management enumeration/deletion works over CTAP2 (e.g. via `fido2-token -L -r` / `-D`, or a browser's own passkey manager where supported) but there's no standalone CLI for it yet.

## Status

tpm-fido has been tested to work with Chrome and Firefox on Linux, including CTAP2 resident-key registration/authentication against webauthn.io and GitHub.

## Building

```
# in the root directory of tpm-fido run:
go build
```

## Running

In order to run `tpm-fido` you will need permission to access `/dev/tpmrm0`. On Ubuntu and Arch, you can add your user to the `tss` group.

Your user also needs permission to access `/dev/uhid` so that `tpm-fido` can appear to be a USB device.
I use the following udev rule to set the appropriate `uhid` permissions:

```
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="SOME_UHID_GROUP_MY_USER_BELONGS_TO", MODE="0660"
```

To ensure the above udev rule gets triggered, I also add the `uhid` module to `/etc/modules-load.d/uhid.conf` so that it loads at boot.

To run:

```
# as a user that has permission to read and write to /dev/tpmrm0:
./tpm-fido
```
Note: do not run with `sudo` or as root, as it will not work.

## Dependencies

tpm-fido requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
