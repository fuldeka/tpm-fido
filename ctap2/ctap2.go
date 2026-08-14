// Package ctap2 implements the subset of the CTAP2 (Client to Authenticator
// Protocol 2) CBOR command set needed to serve WebAuthn discoverable
// (resident key) credentials over the existing tpm-fido HID transport:
// authenticatorGetInfo, authenticatorMakeCredential, authenticatorGetAssertion.
package ctap2

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ctap2EncMode enforces CTAP2 canonical CBOR encoding (deterministic map
// key ordering, definite-length encoding), as required by RFC 8949 §4.2.1
// and the CTAP2 spec. The default cbor.Marshal mode does not guarantee
// canonical map key order, which libfido2 (and other strict CTAP2 clients)
// reject with FIDO_ERR_RX_INVALID_CBOR.
var ctap2EncMode = func() cbor.EncMode {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

// CTAP2 command byte, the first byte of the CBOR message payload.
const (
	CmdMakeCredential              = 0x01
	CmdGetAssertion                = 0x02
	CmdGetInfo                     = 0x04
	CmdClientPIN                   = 0x06
	CmdGetNextAssertion            = 0x08
	CmdCredentialManagement        = 0x0A
	CmdCredentialManagementPreview = 0x41
)

// authenticatorCredentialManagement subcommands (CTAP 2.1 §6.8).
const (
	CredMgmtSubGetCredsMetadata          = 0x01
	CredMgmtSubEnumerateRPsBegin         = 0x02
	CredMgmtSubEnumerateRPsGetNextRP     = 0x03
	CredMgmtSubEnumerateCredsBegin       = 0x04
	CredMgmtSubEnumerateCredsGetNextCred = 0x05
	CredMgmtSubDeleteCredential          = 0x06
)

// CTAP2 status codes (subset).
const (
	StatusSuccess            byte = 0x00
	StatusInvalidCommand     byte = 0x01
	StatusInvalidParameter   byte = 0x02
	StatusInvalidCredential  byte = 0x22
	StatusMissingParameter   byte = 0x14
	StatusCredentialExcluded byte = 0x19
	StatusKeepAliveCancel    byte = 0x2D
	StatusNoCredentials      byte = 0x2E
	StatusOperationDenied    byte = 0x27
	StatusUnsupportedOption  byte = 0x2C
	StatusPinBlocked         byte = 0x32 // PIN/UV retries exhausted; authenticator locked out
	StatusPinAuthInvalid     byte = 0x33 // pinUvAuthParam was supplied but did not verify
	StatusPinRequired        byte = 0x36 // pinUvAuthParam was required but not supplied at all
	StatusOther              byte = 0x7F
)

// arbitrary but fixed AAGUID identifying this authenticator model.
// Generated once for tpm-fido; not a registered/vendor-issued AAGUID.
var AAGUID = [16]byte{
	0x74, 0x70, 0x6d, 0x2d, 0x66, 0x69, 0x64, 0x6f,
	0x2d, 0x72, 0x65, 0x73, 0x69, 0x64, 0x65, 0x6e,
}

type getInfoResponse struct {
	Versions           []string        `cbor:"1,keyasint"`
	AAGUID             []byte          `cbor:"3,keyasint"`
	Options            map[string]bool `cbor:"4,keyasint"`
	PinUvAuthProtocols []int           `cbor:"6,keyasint"`
}

// EncodeGetInfoResponse builds the authenticatorGetInfo CBOR response body.
// rk:true + up:true advertise resident-key and user-presence support so
// GitHub and other RPs that require rk will accept this authenticator.
// clientPin reflects whether a PIN has actually been set (CTAP2 clients,
// notably libfido2, gate credential-management access on this being true,
// so it must track real PIN state rather than being hardcoded).
//
// The "uv" option (built-in user verification, a la Windows Hello / Touch
// ID) is gated on internalUV. Per CTAP2 spec, uv:true means the authenticator
// can verify the user on its *own* side without the platform sending a
// pinUvAuthParam derived from a browser-collected PIN. When internalUV is on
// (and a PIN exists to back it) we advertise uv:true + pinUvAuthToken +
// FIDO_2_1, and browsers drive getPinUvAuthTokenUsingUvWithPermissions so we
// collect the PIN in our own system dialog -- no browser PIN box. When it's
// off we behave as a plain clientPIN authenticator (the browser collects the
// PIN). Advertising uv:true is only safe alongside the getUvToken/
// getUVRetries handlers; historically advertising it *without* them made
// Chrome loop on MakeCredential forever, always failing PIN_REQUIRED.
func EncodeGetInfoResponse(clientPinSet, internalUV bool) ([]byte, error) {
	// Internal UV needs a PIN to actually verify against, so only light it up
	// when a PIN is set.
	helloMode := internalUV && clientPinSet

	versions := []string{"U2F_V2", "FIDO_2_0"}
	options := map[string]bool{
		"rk":        true,
		"up":        true,
		"plat":      false,
		"clientPin": clientPinSet,
		"credMgmt":  true,
	}
	if helloMode {
		versions = append(versions, "FIDO_2_1")
		options["uv"] = true
		options["pinUvAuthToken"] = true
	}

	resp := getInfoResponse{
		Versions:           versions,
		AAGUID:             AAGUID[:],
		Options:            options,
		PinUvAuthProtocols: []int{1},
	}
	return ctap2EncMode.Marshal(resp)
}

type pubKeyCredParam struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

type rpEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name"`
}

type userEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name"`
	DisplayName string `cbor:"displayName"`
}

// MakeCredentialRequest is the decoded subset of the CTAP2
// authenticatorMakeCredential request parameters this authenticator uses.
type MakeCredentialRequest struct {
	ClientDataHash    []byte
	RP                rpEntity
	User              userEntity
	PubKeyCredParams  []pubKeyCredParam
	ExcludeList       [][]byte
	ResidentKey       bool
	UserVerification  bool
	PinUvAuthParam    []byte
	PinUvAuthProtocol int
}

type makeCredentialCbor struct {
	ClientDataHash    []byte                 `cbor:"1,keyasint"`
	RP                rpEntity               `cbor:"2,keyasint"`
	User              userEntity             `cbor:"3,keyasint"`
	PubKeyCredParams  []pubKeyCredParam      `cbor:"4,keyasint"`
	ExcludeList       []credDescriptor       `cbor:"5,keyasint,omitempty"`
	Extensions        map[string]interface{} `cbor:"6,keyasint,omitempty"`
	Options           map[string]bool        `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam    []byte                 `cbor:"8,keyasint,omitempty"`
	PinUvAuthProtocol int                    `cbor:"9,keyasint,omitempty"`
}

func DecodeMakeCredentialRequest(body []byte) (*MakeCredentialRequest, error) {
	var req makeCredentialCbor
	if err := cbor.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode makeCredential params: %w", err)
	}

	if len(req.ClientDataHash) != 32 {
		return nil, fmt.Errorf("invalid clientDataHash length: %d", len(req.ClientDataHash))
	}
	if req.RP.ID == "" {
		return nil, fmt.Errorf("missing rp.id")
	}

	out := &MakeCredentialRequest{
		ClientDataHash:    req.ClientDataHash,
		RP:                req.RP,
		User:              req.User,
		PubKeyCredParams:  req.PubKeyCredParams,
		PinUvAuthParam:    req.PinUvAuthParam,
		PinUvAuthProtocol: req.PinUvAuthProtocol,
	}
	for _, c := range req.ExcludeList {
		out.ExcludeList = append(out.ExcludeList, c.ID)
	}

	if req.Options != nil {
		out.ResidentKey = req.Options["rk"]
		out.UserVerification = req.Options["uv"]
	}

	return out, nil
}

// authenticatorData flags.
const (
	flagUP byte = 1 << 0
	flagUV byte = 1 << 2
	flagAT byte = 1 << 6
)

// BuildAuthData constructs the CTAP2 authenticatorData structure. When
// credID/pubKeyX/pubKeyY are non-nil the attestedCredentialData block
// (AAGUID + credId + COSE public key) is included, as required for
// MakeCredential responses; omit them for GetAssertion.
func BuildAuthData(rpID string, userPresent, userVerified bool, signCount uint32, credID []byte, pubKeyX, pubKeyY []byte) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))

	var flags byte
	if userPresent {
		flags |= flagUP
	}
	if userVerified {
		flags |= flagUV
	}

	buf := make([]byte, 0, 128)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flags)

	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, signCount)
	buf = append(buf, countBytes...)

	if credID != nil {
		flags |= flagAT
		buf[32] = flags

		buf = append(buf, AAGUID[:]...)

		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
		buf = append(buf, credIDLen...)
		buf = append(buf, credID...)

		coseKey, err := encodeCOSEKey(pubKeyX, pubKeyY)
		if err != nil {
			return nil, err
		}
		buf = append(buf, coseKey...)
	}

	return buf, nil
}

// COSE_Key for an EC2 P-256 public key (RFC 9053).
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func encodeCOSEKey(x, y []byte) ([]byte, error) {
	key := coseKey{
		Kty: 2,  // EC2
		Alg: -7, // ES256
		Crv: 1,  // P-256
		X:   pad32(x),
		Y:   pad32(y),
	}
	return ctap2EncMode.Marshal(key)
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

type makeCredentialResponse struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData []byte                 `cbor:"2,keyasint"`
	AttStmt  map[string]interface{} `cbor:"3,keyasint"`
}

// EncodeMakeCredentialResponse builds the CBOR attestationObject response
// body for authenticatorMakeCredential, using packed self-attestation.
func EncodeMakeCredentialResponse(authData []byte, sig []byte, attestationCertDER []byte) ([]byte, error) {
	resp := makeCredentialResponse{
		Fmt:      "packed",
		AuthData: authData,
		AttStmt: map[string]interface{}{
			"alg": -7, // ES256
			"sig": sig,
			"x5c": []interface{}{attestationCertDER},
		},
	}
	return ctap2EncMode.Marshal(resp)
}

type getAssertionCbor struct {
	RPID              string           `cbor:"1,keyasint"`
	ClientDataHash    []byte           `cbor:"2,keyasint"`
	AllowList         []credDescriptor `cbor:"3,keyasint,omitempty"`
	Options           map[string]bool  `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam    []byte           `cbor:"6,keyasint,omitempty"`
	PinUvAuthProtocol int              `cbor:"7,keyasint,omitempty"`
}

type credDescriptor struct {
	Type string `cbor:"type"`
	ID   []byte `cbor:"id"`
}

type GetAssertionRequest struct {
	RPID              string
	ClientDataHash    []byte
	AllowList         [][]byte
	UserPresence      bool
	UserVerification  bool
	PinUvAuthParam    []byte
	PinUvAuthProtocol int
}

func DecodeGetAssertionRequest(body []byte) (*GetAssertionRequest, error) {
	var req getAssertionCbor
	if err := cbor.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode getAssertion params: %w", err)
	}

	if req.RPID == "" {
		return nil, fmt.Errorf("missing rpId")
	}
	if len(req.ClientDataHash) != 32 {
		return nil, fmt.Errorf("invalid clientDataHash length: %d", len(req.ClientDataHash))
	}

	out := &GetAssertionRequest{
		RPID:              req.RPID,
		ClientDataHash:    req.ClientDataHash,
		PinUvAuthParam:    req.PinUvAuthParam,
		PinUvAuthProtocol: req.PinUvAuthProtocol,
		// up defaults to true per CTAP2 spec unless explicitly set false
		// (used by clients for a silent/conditional-mediation probe).
		UserPresence: true,
	}
	for _, c := range req.AllowList {
		out.AllowList = append(out.AllowList, c.ID)
	}
	if req.Options != nil {
		if up, ok := req.Options["up"]; ok {
			out.UserPresence = up
		}
		out.UserVerification = req.Options["uv"]
	}

	return out, nil
}

type getAssertionResponse struct {
	Credential credDescriptor `cbor:"1,keyasint"`
	AuthData   []byte         `cbor:"2,keyasint"`
	Signature  []byte         `cbor:"3,keyasint"`
	User       *userEntity    `cbor:"4,keyasint,omitempty"`
}

// EncodeGetAssertionResponse builds the CBOR response body for
// authenticatorGetAssertion. userHandle must be populated for discoverable
// (resident) credentials per the WebAuthn spec; the user (field 4) is
// omitted entirely when userID is empty, since CTAP2 requires it be absent
// rather than present-with-null for non-discoverable assertions.
func EncodeGetAssertionResponse(credID []byte, authData []byte, sig []byte, userID []byte, userName string) ([]byte, error) {
	resp := getAssertionResponse{
		Credential: credDescriptor{Type: "public-key", ID: credID},
		AuthData:   authData,
		Signature:  sig,
	}
	if len(userID) > 0 {
		resp.User = &userEntity{
			ID:   userID,
			Name: userName,
		}
	}
	return ctap2EncMode.Marshal(resp)
}

// credentialManagementCbor is the CBOR request body for
// authenticatorCredentialManagement: a subcommand byte plus optional
// subcommand-specific params and a pinUvAuthToken proof (fields 3/4).
// SubCommandParams is captured as raw CBOR bytes (not decoded inline)
// because the exact bytes as sent by the platform -- not a re-encoding --
// are part of the message pinUvAuthParam authenticates.
type credentialManagementCbor struct {
	SubCommand        byte            `cbor:"1,keyasint"`
	SubCommandParams  cbor.RawMessage `cbor:"2,keyasint,omitempty"`
	PinUvAuthProtocol int             `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte          `cbor:"4,keyasint,omitempty"`
}

type CredentialManagementRequest struct {
	SubCommand        byte
	RPIDHash          []byte
	CredID            []byte
	PinUvAuthProtocol int
	PinUvAuthParam    []byte
	// AuthenticatedMessage is subCommand||subCommandParams exactly as
	// received (subCommandParams as raw bytes, or omitted entirely if the
	// platform sent no params), which is the message pinUvAuthParam
	// authenticates per CTAP2 spec §6.8.
	AuthenticatedMessage []byte
}

// subcommand param map keys (CTAP 2.1 §6.8).
const (
	paramRPIDHash     = 0x01
	paramCredentialID = 0x02
)

func DecodeCredentialManagementRequest(body []byte) (*CredentialManagementRequest, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty credentialManagement request")
	}

	var req credentialManagementCbor
	if err := cbor.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode credentialManagement params: %w", err)
	}

	out := &CredentialManagementRequest{
		SubCommand:        req.SubCommand,
		PinUvAuthProtocol: req.PinUvAuthProtocol,
		PinUvAuthParam:    req.PinUvAuthParam,
	}

	out.AuthenticatedMessage = append([]byte{req.SubCommand}, req.SubCommandParams...)

	if len(req.SubCommandParams) > 0 {
		var params map[int]interface{}
		if err := cbor.Unmarshal(req.SubCommandParams, &params); err != nil {
			return nil, fmt.Errorf("decode subCommandParams: %w", err)
		}
		if v, ok := params[paramRPIDHash]; ok {
			if b, ok := v.([]byte); ok {
				out.RPIDHash = b
			}
		}
		if v, ok := params[paramCredentialID]; ok {
			// credentialId is itself a PublicKeyCredentialDescriptor map
			// ({"id": bstr, "type": tstr}); fxamacker decodes nested maps
			// with non-string int keys into map[interface{}]interface{}.
			if m, ok := v.(map[interface{}]interface{}); ok {
				if id, ok := m["id"].([]byte); ok {
					out.CredID = id
				}
			}
		}
	}

	return out, nil
}

type getCredsMetadataResponse struct {
	ExistingResidentCredentialsCount       int `cbor:"1,keyasint"`
	MaxPossibleRemainingResidentCredsCount int `cbor:"2,keyasint"`
}

// EncodeGetCredsMetadataResponse builds the response for the
// getCredsMetadata subcommand. tpm-fido has no fixed credential capacity
// (limited only by disk), so remaining count is reported as a large,
// arbitrary headroom figure rather than a real hardware limit.
func EncodeGetCredsMetadataResponse(existingCount int) ([]byte, error) {
	resp := getCredsMetadataResponse{
		ExistingResidentCredentialsCount:       existingCount,
		MaxPossibleRemainingResidentCredsCount: 1000,
	}
	return ctap2EncMode.Marshal(resp)
}

type enumerateRPsResponse struct {
	RP       rpEntity `cbor:"3,keyasint"`
	RPIDHash []byte   `cbor:"4,keyasint"`
	TotalRPs int      `cbor:"5,keyasint,omitempty"`
}

// EncodeEnumerateRPResponse builds one response entry for
// enumerateRPsBegin/enumerateRPsGetNextRP. totalRPs is only meaningful (and
// only sent) on the first (Begin) response of the enumeration.
func EncodeEnumerateRPResponse(rpID string, totalRPs int, includeTotal bool) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	resp := enumerateRPsResponse{
		RP:       rpEntity{ID: rpID},
		RPIDHash: rpIDHash[:],
	}
	if includeTotal {
		resp.TotalRPs = totalRPs
	}
	return ctap2EncMode.Marshal(resp)
}

type enumerateCredsResponse struct {
	User         userEntity     `cbor:"6,keyasint"`
	CredentialID credDescriptor `cbor:"7,keyasint"`
	TotalCreds   int            `cbor:"9,keyasint,omitempty"`
}

// EncodeEnumerateCredentialResponse builds one response entry for
// enumerateCredentialsBegin/enumerateCredentialsGetNextCredential.
// totalCreds is only sent on the first (Begin) response for that rpId.
func EncodeEnumerateCredentialResponse(credID []byte, userID []byte, userName string, totalCreds int, includeTotal bool) ([]byte, error) {
	resp := enumerateCredsResponse{
		User:         userEntity{ID: userID, Name: userName},
		CredentialID: credDescriptor{Type: "public-key", ID: credID},
	}
	if includeTotal {
		resp.TotalCreds = totalCreds
	}
	return ctap2EncMode.Marshal(resp)
}

// authenticatorClientPIN subcommands (CTAP2 spec §6.5.5) this authenticator
// implements. getPINToken (0x05) is the pre-2.1 alias for
// getPinUvAuthTokenUsingPinWithPermissions and is what libfido2 uses by
// default; the newer permissions-scoped variant (0x09) is not implemented
// since this authenticator has no permission-scoping to enforce.
// getPINRetries (0x01) is called by some platforms (e.g. Chrome) before
// getKeyAgreement to decide whether/how to prompt for a PIN.
const (
	ClientPINSubGetPINRetries   = 0x01
	ClientPINSubGetKeyAgreement = 0x02
	ClientPINSubSetPIN          = 0x03
	ClientPINSubChangePIN       = 0x04
	ClientPINSubGetPINToken     = 0x05
	// ClientPINSubGetUvToken (getPinUvAuthTokenUsingUvWithPermissions) is the
	// CTAP 2.1 internal-UV token request: the browser asks us to mint a
	// UV-backed pinUvAuthToken and we perform user verification on our own
	// side (a system PIN dialog) instead of receiving a browser-collected
	// pinHashEnc. Only meaningful when getInfo advertised uv:true.
	ClientPINSubGetUvToken = 0x06
	// ClientPINSubGetUVRetries (getUVRetries) reports remaining built-in-UV
	// attempts. Chrome calls this before getUvToken to decide whether
	// internal UV is usable; if we reject it, Chrome abandons the
	// authenticator and falls back to other transports.
	ClientPINSubGetUVRetries = 0x07
)

type coseKeyPub struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

type clientPINCbor struct {
	PinUvAuthProtocol int        `cbor:"1,keyasint"`
	SubCommand        byte       `cbor:"2,keyasint"`
	KeyAgreement      coseKeyPub `cbor:"3,keyasint"`
	PinUvAuthParam    []byte     `cbor:"4,keyasint"`
	NewPinEnc         []byte     `cbor:"5,keyasint"`
	PinHashEnc        []byte     `cbor:"6,keyasint"`
	// CTAP 2.1 permission-scoped token fields (used by getUvToken).
	Permissions int    `cbor:"9,keyasint,omitempty"`
	RpID        string `cbor:"10,keyasint,omitempty"`
}

// ClientPINRequest is the decoded subset of an authenticatorClientPIN
// request this authenticator uses.
type ClientPINRequest struct {
	SubCommand        byte
	PinUvAuthProtocol int
	PeerKeyX          []byte
	PeerKeyY          []byte
	PinUvAuthParam    []byte
	NewPinEnc         []byte
	PinHashEnc        []byte
	Permissions       int
	RpID              string
}

func DecodeClientPINRequest(body []byte) (*ClientPINRequest, error) {
	var req clientPINCbor
	if err := cbor.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode clientPIN params: %w", err)
	}

	return &ClientPINRequest{
		SubCommand:        req.SubCommand,
		PinUvAuthProtocol: req.PinUvAuthProtocol,
		PeerKeyX:          req.KeyAgreement.X,
		PeerKeyY:          req.KeyAgreement.Y,
		PinUvAuthParam:    req.PinUvAuthParam,
		NewPinEnc:         req.NewPinEnc,
		PinHashEnc:        req.PinHashEnc,
		Permissions:       req.Permissions,
		RpID:              req.RpID,
	}, nil
}

type clientPINGetKeyAgreementResponse struct {
	KeyAgreement coseKeyPub `cbor:"1,keyasint"`
}

// EncodeClientPINKeyAgreementResponse builds the response for the
// getKeyAgreement subcommand: this authenticator's ECDH public key as a
// COSE_Key.
func EncodeClientPINKeyAgreementResponse(x, y []byte) ([]byte, error) {
	resp := clientPINGetKeyAgreementResponse{
		KeyAgreement: coseKeyPub{Kty: 2, Alg: -25, Crv: 1, X: x, Y: y},
	}
	return ctap2EncMode.Marshal(resp)
}

type clientPINGetTokenResponse struct {
	PinUvAuthToken []byte `cbor:"2,keyasint"`
}

// EncodeClientPINTokenResponse builds the response for the getPINToken
// subcommand: the pinUvAuthToken, encrypted with the shared secret.
func EncodeClientPINTokenResponse(encryptedToken []byte) ([]byte, error) {
	resp := clientPINGetTokenResponse{PinUvAuthToken: encryptedToken}
	return ctap2EncMode.Marshal(resp)
}

type clientPINGetRetriesResponse struct {
	PinRetries int `cbor:"3,keyasint"`
}

// EncodeClientPINRetriesResponse builds the response for the
// getPINRetries subcommand: how many PIN attempts remain before lockout.
// Some CTAP2 platforms (e.g. Chrome) call this before getKeyAgreement to
// decide whether/how to prompt the user, so an authenticator that doesn't
// implement it can leave the platform stuck never attempting the PIN
// protocol at all.
func EncodeClientPINRetriesResponse(retriesLeft int) ([]byte, error) {
	resp := clientPINGetRetriesResponse{PinRetries: retriesLeft}
	return ctap2EncMode.Marshal(resp)
}

type clientPINGetUVRetriesResponse struct {
	UVRetries int `cbor:"5,keyasint"`
}

// EncodeClientPINUVRetriesResponse builds the response for the getUVRetries
// subcommand (0x07). Chrome calls this before getUvToken to decide whether
// built-in UV is usable; rejecting it makes Chrome abandon the authenticator
// and fall back to other transports. Our built-in UV is PIN-backed, so we
// mirror the PIN retry counter.
func EncodeClientPINUVRetriesResponse(retriesLeft int) ([]byte, error) {
	resp := clientPINGetUVRetriesResponse{UVRetries: retriesLeft}
	return ctap2EncMode.Marshal(resp)
}
