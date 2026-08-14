package ctap2

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestBuildAuthDataFlags(t *testing.T) {
	cases := []struct {
		name               string
		up, uv             bool
		wantUP, wantUV, at bool
	}{
		{"none", false, false, false, false, false},
		{"up only", true, false, true, false, false},
		{"up and uv", true, true, true, true, false},
		{"uv without up", false, true, false, true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			authData, err := BuildAuthData("example.com", c.up, c.uv, 1, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(authData) != 37 {
				t.Fatalf("expected 37 byte authData with no attested cred data, got %d", len(authData))
			}
			flags := authData[32]
			gotUP := flags&flagUP != 0
			gotUV := flags&flagUV != 0
			gotAT := flags&flagAT != 0
			if gotUP != c.wantUP {
				t.Errorf("UP flag: got %v want %v", gotUP, c.wantUP)
			}
			if gotUV != c.wantUV {
				t.Errorf("UV flag: got %v want %v", gotUV, c.wantUV)
			}
			if gotAT != false {
				t.Errorf("AT flag should be unset with nil credID, got %v", gotAT)
			}
		})
	}
}

func TestBuildAuthDataWithAttestedCredData(t *testing.T) {
	credID := []byte("some-cred-id")
	x := bytes.Repeat([]byte{0xAA}, 32)
	y := bytes.Repeat([]byte{0xBB}, 32)

	authData, err := BuildAuthData("example.com", true, true, 5, credID, x, y)
	if err != nil {
		t.Fatal(err)
	}

	flags := authData[32]
	if flags&flagAT == 0 {
		t.Fatal("expected AT flag to be set when credID is provided")
	}

	rpIDHash := authData[:32]
	wantHash := sha256.Sum256([]byte("example.com"))
	if !bytes.Equal(rpIDHash, wantHash[:]) {
		t.Fatal("rpIdHash mismatch")
	}

	aaguid := authData[37:53]
	if !bytes.Equal(aaguid, AAGUID[:]) {
		t.Fatal("AAGUID mismatch")
	}

	credIDLen := int(authData[53])<<8 | int(authData[54])
	if credIDLen != len(credID) {
		t.Fatalf("credIDLen mismatch: got %d want %d", credIDLen, len(credID))
	}
	gotCredID := authData[55 : 55+credIDLen]
	if !bytes.Equal(gotCredID, credID) {
		t.Fatal("credID mismatch")
	}
}

func TestPad32(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{"short", []byte{1, 2, 3}, 32},
		{"exact", bytes.Repeat([]byte{1}, 32), 32},
		{"long", bytes.Repeat([]byte{1}, 40), 32},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pad32(c.in)
			if len(got) != c.want {
				t.Fatalf("got len %d want %d", len(got), c.want)
			}
		})
	}

	// short input is left-padded with zeros, value preserved at the end
	got := pad32([]byte{0xAA, 0xBB})
	if got[30] != 0xAA || got[31] != 0xBB {
		t.Fatalf("expected value preserved at end of padding, got %x", got)
	}
	for _, b := range got[:30] {
		if b != 0 {
			t.Fatalf("expected leading zero padding, got %x", got)
		}
	}

	// long input is truncated to the low 32 bytes
	long := append(bytes.Repeat([]byte{0xFF}, 8), bytes.Repeat([]byte{0x11}, 32)...)
	got = pad32(long)
	if !bytes.Equal(got, bytes.Repeat([]byte{0x11}, 32)) {
		t.Fatalf("expected truncation to low 32 bytes, got %x", got)
	}
}

func TestDecodeMakeCredentialRequestValidation(t *testing.T) {
	valid := makeCredentialCbor{
		ClientDataHash: bytes.Repeat([]byte{1}, 32),
		RP:             rpEntity{ID: "example.com", Name: "Example"},
		User:           userEntity{ID: []byte("user1"), Name: "alice"},
	}
	body, err := cbor.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeMakeCredentialRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if req.RP.ID != "example.com" {
		t.Fatalf("unexpected RP.ID: %s", req.RP.ID)
	}

	badHash := valid
	badHash.ClientDataHash = []byte{1, 2, 3}
	body, _ = cbor.Marshal(badHash)
	if _, err := DecodeMakeCredentialRequest(body); err == nil {
		t.Fatal("expected error for invalid clientDataHash length")
	}

	noRPID := valid
	noRPID.RP = rpEntity{ID: "", Name: "Example"}
	body, _ = cbor.Marshal(noRPID)
	if _, err := DecodeMakeCredentialRequest(body); err == nil {
		t.Fatal("expected error for missing rp.id")
	}
}

func TestDecodeMakeCredentialRequestOptions(t *testing.T) {
	req := makeCredentialCbor{
		ClientDataHash: bytes.Repeat([]byte{1}, 32),
		RP:             rpEntity{ID: "example.com"},
		User:           userEntity{ID: []byte("user1")},
		Options:        map[string]bool{"rk": true, "uv": true},
	}
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMakeCredentialRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.ResidentKey {
		t.Fatal("expected ResidentKey=true from rk option")
	}
	if !decoded.UserVerification {
		t.Fatal("expected UserVerification=true from uv option")
	}
}

func TestDecodeGetAssertionRequestDefaults(t *testing.T) {
	req := getAssertionCbor{
		RPID:           "example.com",
		ClientDataHash: bytes.Repeat([]byte{2}, 32),
	}
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGetAssertionRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.UserPresence {
		t.Fatal("expected UserPresence to default to true")
	}
	if len(decoded.AllowList) != 0 {
		t.Fatalf("expected empty AllowList, got %d", len(decoded.AllowList))
	}
}

func TestDecodeGetAssertionRequestAllowListAndOptions(t *testing.T) {
	req := getAssertionCbor{
		RPID:           "example.com",
		ClientDataHash: bytes.Repeat([]byte{2}, 32),
		AllowList: []credDescriptor{
			{Type: "public-key", ID: []byte("cred-a")},
			{Type: "public-key", ID: []byte("cred-b")},
		},
		Options: map[string]bool{"up": false, "uv": true},
	}
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGetAssertionRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.UserPresence {
		t.Fatal("expected UserPresence=false when up option explicitly false")
	}
	if !decoded.UserVerification {
		t.Fatal("expected UserVerification=true from uv option")
	}
	if len(decoded.AllowList) != 2 {
		t.Fatalf("expected 2 allowList entries, got %d", len(decoded.AllowList))
	}
	if string(decoded.AllowList[0]) != "cred-a" || string(decoded.AllowList[1]) != "cred-b" {
		t.Fatalf("allowList order/content mismatch: %v", decoded.AllowList)
	}
}

func TestDecodeMakeCredentialRequestPinUvAuthParam(t *testing.T) {
	req := makeCredentialCbor{
		ClientDataHash:    bytes.Repeat([]byte{1}, 32),
		RP:                rpEntity{ID: "example.com"},
		User:              userEntity{ID: []byte("user1")},
		PinUvAuthParam:    []byte("16-byte-hmac-tag"),
		PinUvAuthProtocol: 1,
	}
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMakeCredentialRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PinUvAuthParam, []byte("16-byte-hmac-tag")) {
		t.Fatalf("PinUvAuthParam not decoded: %x", decoded.PinUvAuthParam)
	}
	if decoded.PinUvAuthProtocol != 1 {
		t.Fatalf("PinUvAuthProtocol not decoded: %d", decoded.PinUvAuthProtocol)
	}
}

func TestDecodeGetAssertionRequestPinUvAuthParam(t *testing.T) {
	req := getAssertionCbor{
		RPID:              "example.com",
		ClientDataHash:    bytes.Repeat([]byte{2}, 32),
		PinUvAuthParam:    []byte("16-byte-hmac-tag"),
		PinUvAuthProtocol: 1,
	}
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGetAssertionRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PinUvAuthParam, []byte("16-byte-hmac-tag")) {
		t.Fatalf("PinUvAuthParam not decoded: %x", decoded.PinUvAuthParam)
	}
	if decoded.PinUvAuthProtocol != 1 {
		t.Fatalf("PinUvAuthProtocol not decoded: %d", decoded.PinUvAuthProtocol)
	}
}

func TestEncodeClientPINRetriesResponse(t *testing.T) {
	body, err := EncodeClientPINRetriesResponse(5)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		PinRetries int `cbor:"3,keyasint"`
	}
	if err := cbor.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PinRetries != 5 {
		t.Fatalf("expected pinRetries=5, got %d", decoded.PinRetries)
	}
}

func TestEncodeClientPINUVRetriesResponse(t *testing.T) {
	body, err := EncodeClientPINUVRetriesResponse(7)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		UVRetries int `cbor:"5,keyasint"`
	}
	if err := cbor.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.UVRetries != 7 {
		t.Fatalf("expected uvRetries=7, got %d", decoded.UVRetries)
	}
}

// getInfoOptions decodes just the options map + versions from a getInfo
// response so we can assert what's advertised.
func decodeGetInfo(t *testing.T, body []byte) (map[string]bool, []string) {
	t.Helper()
	var decoded struct {
		Versions []string        `cbor:"1,keyasint"`
		Options  map[string]bool `cbor:"4,keyasint"`
	}
	if err := cbor.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded.Options, decoded.Versions
}

func hasVersion(vs []string, want string) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}

func TestEncodeGetInfoInternalUVGating(t *testing.T) {
	// Hello mode requires BOTH the toggle on AND a PIN set.
	cases := []struct {
		name              string
		pinSet, internal  bool
		wantUV, want2_1   bool
	}{
		{"no-pin-toggle-off", false, false, false, false},
		{"no-pin-toggle-on", false, true, false, false},
		{"pin-toggle-off", true, false, false, false},
		{"pin-toggle-on", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := EncodeGetInfoResponse(tc.pinSet, tc.internal)
			if err != nil {
				t.Fatal(err)
			}
			opts, versions := decodeGetInfo(t, body)

			if got := opts["uv"]; got != tc.wantUV {
				t.Errorf("uv=%t, want %t", got, tc.wantUV)
			}
			if got := opts["pinUvAuthToken"]; got != tc.wantUV {
				t.Errorf("pinUvAuthToken=%t, want %t", got, tc.wantUV)
			}
			if got := hasVersion(versions, "FIDO_2_1"); got != tc.want2_1 {
				t.Errorf("FIDO_2_1 advertised=%t, want %t", got, tc.want2_1)
			}
			// clientPin option always tracks the PIN-set state regardless.
			if got := opts["clientPin"]; got != tc.pinSet {
				t.Errorf("clientPin=%t, want %t", got, tc.pinSet)
			}
		})
	}
}

func TestDecodeClientPINRequestPermissionsAndRpID(t *testing.T) {
	req := clientPINCbor{
		PinUvAuthProtocol: 1,
		SubCommand:        ClientPINSubGetUvToken,
		Permissions:       0x01,
		RpID:              "example.com",
	}
	body, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClientPINRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Permissions != 0x01 {
		t.Errorf("permissions=%d, want 1", decoded.Permissions)
	}
	if decoded.RpID != "example.com" {
		t.Errorf("rpID=%q, want example.com", decoded.RpID)
	}
}

func TestDecodeGetAssertionRequestValidation(t *testing.T) {
	if _, err := DecodeGetAssertionRequest([]byte{0xA0}); err == nil {
		t.Fatal("expected error for missing rpId")
	}

	badHash := getAssertionCbor{RPID: "example.com", ClientDataHash: []byte{1}}
	body, _ := cbor.Marshal(badHash)
	if _, err := DecodeGetAssertionRequest(body); err == nil {
		t.Fatal("expected error for invalid clientDataHash length")
	}
}
