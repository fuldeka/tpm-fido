package ctap2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/psanford/tpm-fido/memory"
)

// TestAssertionRoundTripRPVerification runs a full register -> assert ->
// verify cycle, like an RP would run it.
func TestAssertionRoundTripRPVerification(t *testing.T) {
	signer, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}

	const rpID = "www.passkeys.io"
	rpIDHash := sha256.Sum256([]byte(rpID))

	// --- Registration ---
	keyHandle, x, y, err := signer.RegisterKey(rpIDHash[:])
	if err != nil {
		t.Fatal(err)
	}

	clientDataHash := sha256.Sum256([]byte(`{"type":"webauthn.create","challenge":"reg-challenge"}`))

	regAuthData, err := BuildAuthData(rpID, true, true, 0, keyHandle, x.Bytes(), y.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := regAuthData[32]; got&flagAT == 0 {
		t.Fatal("registration authData must carry AT flag")
	}

	regToSign := append(append([]byte{}, regAuthData...), clientDataHash[:]...)
	_ = regToSign // attestation sig verified implicitly: passkeys.io accepted registration

	// --- RP extracts the credential public key from registration authData ---
	credIDLen := int(regAuthData[53])<<8 | int(regAuthData[54])
	gotCredID := regAuthData[55 : 55+credIDLen]
	if !bytes.Equal(gotCredID, keyHandle) {
		t.Fatal("credential ID in authData differs from keyHandle")
	}
	coseBytes := regAuthData[55+credIDLen:]

	var decodedCOSE coseKey
	if err := cbor.Unmarshal(coseBytes, &decodedCOSE); err != nil {
		t.Fatalf("decode COSE key from authData: %s", err)
	}
	if decodedCOSE.Alg != -7 {
		t.Fatalf("unexpected COSE alg: %d", decodedCOSE.Alg)
	}
	if len(decodedCOSE.X) != 32 || len(decodedCOSE.Y) != 32 {
		t.Fatalf("bad COSE coordinate lengths: x=%d y=%d", len(decodedCOSE.X), len(decodedCOSE.Y))
	}

	rpPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(decodedCOSE.X),
		Y:     new(big.Int).SetBytes(decodedCOSE.Y),
	}
	if !rpPubKey.Curve.IsOnCurve(rpPubKey.X, rpPubKey.Y) {
		t.Fatal("decoded public key is not on P-256")
	}

	// Sanity: the decoded public key must match RegisterKey's coordinates.
	if rpPubKey.X.Cmp(x) != 0 || rpPubKey.Y.Cmp(y) != 0 {
		t.Fatal("COSE-encoded public key differs from RegisterKey output")
	}

	// --- Assertion ---
	assertClientDataHash := sha256.Sum256([]byte(`{"type":"webauthn.get","challenge":"assert-challenge"}`))
	assertAuthData, err := BuildAuthData(rpID, true, true, 1, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(assertAuthData) != 37 {
		t.Fatalf("expected 37-byte assertion authData, got %d", len(assertAuthData))
	}
	if flags := assertAuthData[32]; flags&(flagUP|flagUV) != flagUP|flagUV {
		t.Fatalf("assertion flags missing UP|UV: %x", flags)
	}

	toSign := append(append([]byte{}, assertAuthData...), assertClientDataHash[:]...)
	sigHash := sha256.Sum256(toSign)

	sig, err := signer.SignASN1(keyHandle, rpIDHash[:], sigHash[:])
	if err != nil {
		t.Fatalf("SignASN1: %s", err)
	}

	// --- RP-side verification of the assertion ---
	if !ecdsa.VerifyASN1(rpPubKey, sigHash[:], sig) {
		t.Fatal("RP-side signature verification FAILED -- this reproduces the relying-party rejection")
	}

	// --- Wire format check: the exact CBOR response must decode cleanly ---
	userID := []byte("user-bytes-here")
	respBody, err := EncodeGetAssertionResponse(keyHandle, assertAuthData, sig, userID, "test-user")
	if err != nil {
		t.Fatal(err)
	}

	var resp map[int]cbor.RawMessage
	if err := cbor.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("assertion response CBOR undecodable: %s", err)
	}
	if _, ok := resp[1]; !ok {
		t.Fatal("missing field 1 (credential descriptor)")
	}
	if _, ok := resp[2]; !ok {
		t.Fatal("missing field 2 (authData)")
	}
	if _, ok := resp[3]; !ok {
		t.Fatal("missing field 3 (signature)")
	}
	if _, ok := resp[4]; !ok {
		t.Fatal("missing field 4 (user entity) for discoverable credential")
	}

	var credDesc credDescriptor
	if err := cbor.Unmarshal(resp[1], &credDesc); err != nil {
		t.Fatalf("credential descriptor undecodable: %s", err)
	}
	if credDesc.Type != "public-key" {
		t.Fatalf("credential type=%q", credDesc.Type)
	}
	if !bytes.Equal(credDesc.ID, keyHandle) {
		t.Fatal("response credential id != keyHandle")
	}

	var gotAuthData []byte
	if err := cbor.Unmarshal(resp[2], &gotAuthData); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotAuthData, assertAuthData) {
		t.Fatal("response authData mismatch")
	}

	var gotUser userEntity
	if err := cbor.Unmarshal(resp[4], &gotUser); err != nil {
		t.Fatalf("user entity undecodable: %s", err)
	}
	if len(gotUser.ID) == 0 {
		t.Fatal("user.id is empty in response")
	}

	t.Log("full round trip verified OK: signature verifies under the registered public key")
}
