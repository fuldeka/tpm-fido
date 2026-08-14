package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/psanford/tpm-fido/pinprotocol"
)

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func unb64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Control-socket RPC methods. This is trusted local IPC over a 0600 Unix
// socket (see ctlsocket package) -- unlike the CTAP2/HID PIN protocol,
// there's no need for ECDH-encrypted PIN transport here, since the socket
// itself is already access-controlled by filesystem permissions. The PIN
// is still never stored in plaintext: only its hash ever reaches pinstore.
const (
	MethodListRPs    = "ListRPs"
	MethodListCreds  = "ListCreds"
	MethodDeleteCred = "DeleteCred"
	MethodPINStatus  = "PINStatus"
	MethodSetPIN     = "SetPIN"
	MethodChangePIN  = "ChangePIN"
	// Clears a failed-attempt lockout (retry counter -> max) without
	// changing the PIN or credentials. Recovery path for when the PIN got
	// locked out and ChangePIN can no longer verify the old PIN.
	MethodResetPINRetries = "ResetPINRetries"
	// Internal-UV ("Hello mode") toggle.
	MethodGetInternalUV = "GetInternalUV"
	MethodSetInternalUV = "SetInternalUV"
)

type internalUVResult struct {
	Enabled bool `json:"enabled"`
}

type setInternalUVParams struct {
	Enabled bool `json:"enabled"`
}

type CredentialInfo struct {
	CredentialID string `json:"credential_id"` // base64
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	SignCount    uint32 `json:"sign_count"`
}

type PINStatusResult struct {
	IsSet       bool `json:"is_set"`
	RetriesLeft int  `json:"retries_left"`
}

type deleteCredParams struct {
	RPID         string `json:"rp_id"`
	CredentialID string `json:"credential_id"` // base64
}

type setPINParams struct {
	NewPIN string `json:"new_pin"`
}

type changePINParams struct {
	OldPIN string `json:"old_pin"`
	NewPIN string `json:"new_pin"`
}

// handleCtlRequest is the ctlsocket.Handler for this server: dispatches by
// method name to the resident/PIN stores directly (no CTAP2/CBOR/ECDH
// involved -- this is local IPC, not the FIDO2 wire protocol).
func (s *server) handleCtlRequest(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case MethodListRPs:
		return s.resident.RPIDs(), nil

	case MethodListCreds:
		var p struct {
			RPID string `json:"rp_id"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		creds := s.resident.ByRPID(p.RPID)
		out := make([]CredentialInfo, 0, len(creds))
		for _, c := range creds {
			out = append(out, CredentialInfo{
				CredentialID: b64(c.CredentialID),
				RPID:         c.RPID,
				UserName:     c.UserName,
				SignCount:    c.SignCount,
			})
		}
		return out, nil

	case MethodDeleteCred:
		var p deleteCredParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		credID, err := unb64(p.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("invalid credential_id: %w", err)
		}
		if err := s.resident.Delete(p.RPID, credID); err != nil {
			return nil, err
		}
		return struct{}{}, nil

	case MethodPINStatus:
		return PINStatusResult{
			IsSet:       s.pins.IsSet(),
			RetriesLeft: s.pins.RetriesLeft(),
		}, nil

	case MethodSetPIN:
		var p setPINParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if s.pins.IsSet() {
			return nil, fmt.Errorf("PIN already set; use ChangePIN")
		}
		if err := validatePIN(p.NewPIN); err != nil {
			return nil, err
		}
		if err := s.pins.SetPIN(pinprotocol.HashPIN(p.NewPIN)); err != nil {
			return nil, err
		}
		return struct{}{}, nil

	case MethodChangePIN:
		var p changePINParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if !s.pins.IsSet() {
			return nil, fmt.Errorf("no PIN set; use SetPIN")
		}
		match, err := s.pins.Verify(pinprotocol.HashPIN(p.OldPIN))
		if err != nil {
			return nil, err
		}
		if !match {
			return nil, fmt.Errorf("incorrect PIN, %d retries left", s.pins.RetriesLeft())
		}
		if err := validatePIN(p.NewPIN); err != nil {
			return nil, err
		}
		if err := s.pins.SetPIN(pinprotocol.HashPIN(p.NewPIN)); err != nil {
			return nil, err
		}
		// Any previously issued CTAP2 pinUvAuthToken is invalidated by a
		// PIN change, same as the ClientPIN changePIN subcommand.
		s.setPinToken(nil)
		return struct{}{}, nil

	case MethodResetPINRetries:
		if err := s.pins.ResetRetries(); err != nil {
			return nil, err
		}
		return PINStatusResult{
			IsSet:       s.pins.IsSet(),
			RetriesLeft: s.pins.RetriesLeft(),
		}, nil

	case MethodGetInternalUV:
		return internalUVResult{Enabled: s.uvcfg.InternalUV()}, nil

	case MethodSetInternalUV:
		var p setInternalUVParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if err := s.uvcfg.SetInternalUV(p.Enabled); err != nil {
			return nil, err
		}
		return internalUVResult{Enabled: p.Enabled}, nil

	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

// validatePIN enforces the CTAP2 minimum PIN length (4 UTF-8 code points);
// there's no enforced maximum here since we don't do the 64-byte-padded
// wire encoding locally (this is the plaintext local-IPC path).
func validatePIN(pin string) error {
	if len([]rune(pin)) < 4 {
		return fmt.Errorf("PIN must be at least 4 characters")
	}
	return nil
}
