// Package pinverifier is the PIN-backed implementation of uvmethod.Verifier.
// It collects a PIN in tpm-fido's own pinentry dialog and checks it against
// the pinstore, so CTAP 2.1 internal UV never routes the PIN through the
// browser.
package pinverifier

import (
	"context"
	"log"

	"github.com/psanford/tpm-fido/pinentry"
	"github.com/psanford/tpm-fido/pinprotocol"
	"github.com/psanford/tpm-fido/uvmethod"
)

// PINStore is the subset of *pinstore.Store this verifier needs.
type PINStore interface {
	IsSet() bool
	// Verify takes left-16-bytes-of-SHA-256(PIN), returns match, and a
	// non-nil error when locked out.
	Verify(hash []byte) (bool, error)
	RetriesLeft() int
}

// Verifier verifies the user by PIN entry via pinentry.
type Verifier struct {
	pe  *pinentry.Pinentry
	pin PINStore
}

func New(pe *pinentry.Pinentry, pin PINStore) *Verifier {
	return &Verifier{pe: pe, pin: pin}
}

func (v *Verifier) Name() string { return "pin" }

func (v *Verifier) Verify(ctx context.Context, rpID string) (uvmethod.Outcome, error) {
	if !v.pin.IsSet() {
		// No PIN configured -> internal UV can't be performed. (getInfo
		// gates uv:true on a PIN being set, so we shouldn't normally get
		// here, but be defensive.)
		return uvmethod.Unavailable, nil
	}

	desc := "Verify your identity to sign in"
	if rpID != "" {
		desc = "Verify your identity to sign in to " + rpID
	}

	ch, err := v.pe.CollectPIN(ctx, desc)
	if err != nil {
		log.Printf("pinverifier: CollectPIN err: %s", err)
		return uvmethod.Unavailable, err
	}

	var result pinentry.Result
	select {
	case result = <-ch:
	case <-ctx.Done():
		return uvmethod.Rejected, nil
	}

	if !result.OK || result.PIN == "" {
		// User canceled the dialog or entered nothing.
		return uvmethod.Rejected, nil
	}

	// Left 16 bytes of SHA-256(PIN) -- the CTAP2 pinHash, the same value
	// pinstore stores and compares against for the browser-side PIN path.
	pinHash := pinprotocol.HashPIN(result.PIN)

	// Best-effort scrub of the plaintext PIN.
	result.PIN = ""

	match, err := v.pin.Verify(pinHash)
	if err != nil {
		log.Printf("pinverifier: locked out: %s", err)
		return uvmethod.LockedOut, nil
	}
	if !match {
		log.Printf("pinverifier: PIN mismatch, %d retries left", v.pin.RetriesLeft())
		return uvmethod.Rejected, nil
	}

	return uvmethod.Verified, nil
}
