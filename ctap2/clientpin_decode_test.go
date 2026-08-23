package ctap2

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestDecodeClientPINSpecShape decodes the spec-shaped setPIN request
// {1: proto, 2: subcmd=4, 3: keyAgreement, 4: pinUvAuthParam, 5: newPinEnc}.
func TestDecodeClientPINSpecShape(t *testing.T) {
	payload := map[int]any{
		1: 1,
		2: byte(4),
		3: map[int]any{
			1:  2,
			3:  -25,
			-1: 1,
			-2: bytes.Repeat([]byte{0xAA}, 32),
			-3: bytes.Repeat([]byte{0xBB}, 32),
		},
		4: bytes.Repeat([]byte{0xCC}, 16),
		5: bytes.Repeat([]byte{0xDD}, 64),
	}
	raw, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wire: %x", raw)

	req, err := DecodeClientPINRequest(raw)
	if err != nil {
		t.Fatalf("DecodeClientPINRequest rejected SPEC-COMPLIANT setPIN: %v", err)
	}
	if req.SubCommand != 4 {
		t.Fatalf("subcommand = %d", req.SubCommand)
	}
	if len(req.PeerKeyX) != 32 || len(req.PeerKeyY) != 32 {
		t.Fatalf("peer keys wrong: %d/%d", len(req.PeerKeyX), len(req.PeerKeyY))
	}
	if len(req.NewPinEnc) != 64 {
		t.Fatalf("newPinEnc len = %d", len(req.NewPinEnc))
	}
}

// getUVToken shape: {1:proto, 2:subcmd=9, 9:permissions, 10:rpid}
func TestDecodeClientPINGetUVTokenShape(t *testing.T) {
	payload := map[int]any{
		1: 1,
		2: byte(9),
		3: map[int]any{
			1: 2, 3: -25, -1: 1,
			-2: bytes.Repeat([]byte{0xAA}, 32),
			-3: bytes.Repeat([]byte{0xBB}, 32),
		},
		4:  bytes.Repeat([]byte{0xCC}, 16),
		9:  0x03 | 0x04,
		10: "www.passkeys.io",
	}
	raw, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeClientPINRequest(raw)
	if err != nil {
		t.Fatalf("getUVToken decode failed: %v", err)
	}
	if req.RpID != "www.passkeys.io" {
		t.Fatalf("rpid = %q", req.RpID)
	}
}
