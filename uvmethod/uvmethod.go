// Package uvmethod abstracts how tpm-fido performs *built-in* user
// verification for CTAP 2.1 internal UV (the Windows-Hello-style path, where
// the browser shows no PIN box and the authenticator verifies the user on its
// own side).
//
// Today the only backend is PIN entry via a system pinentry dialog, but the
// getUvToken handler talks to this interface rather than to pinentry
// directly, so a future biometric backend (e.g. custom face recognition) can
// slot in by implementing Verifier without touching the CTAP2 layer.
package uvmethod

import "context"

// Outcome is the result of a user-verification attempt.
type Outcome int

const (
	// Verified: the user was successfully verified.
	Verified Outcome = iota
	// Rejected: the user failed verification (wrong PIN, biometric no-match,
	// or explicit cancel/deny).
	Rejected
	// Unavailable: verification could not be attempted at all (no PIN set,
	// no camera, backend misconfigured). Distinct from Rejected so the
	// caller can map it to a different CTAP status if desired.
	Unavailable
	// LockedOut: too many failed attempts; the backend refuses further tries
	// until reset.
	LockedOut
)

// Verifier performs one built-in user-verification interaction.
//
// rpID is the relying-party the token is being minted for; a backend may show
// it to the user for context. Implementations must respect ctx cancellation
// (e.g. a CTAPHID_CANCEL aborting the operation) and return promptly.
type Verifier interface {
	// Verify runs the interaction and blocks until it resolves, the ctx is
	// canceled, or an internal timeout fires. It must not panic and must
	// return a terminal Outcome.
	Verify(ctx context.Context, rpID string) (Outcome, error)

	// Name is a short identifier for logs ("pin", "face", ...).
	Name() string
}
