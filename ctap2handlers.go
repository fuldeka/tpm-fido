package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"time"

	"github.com/psanford/tpm-fido/attestation"
	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/pinprotocol"
	"github.com/psanford/tpm-fido/residentstore"
)

func (s *server) handleCbor(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	if len(evt.Cbor) == 0 {
		log.Printf("empty cbor message")
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	cmd := evt.Cbor[0]
	body := evt.Cbor[1:]

	switch cmd {
	case ctap2.CmdGetInfo:
		log.Printf("got CTAP2 authenticatorGetInfo")
		resp, err := ctap2.EncodeGetInfoResponse(s.pins.IsSet())
		if err != nil {
			log.Printf("encode getInfo response err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CmdMakeCredential:
		s.handleMakeCredential(parentCtx, token, evt, body)

	case ctap2.CmdGetAssertion:
		s.handleGetAssertion(parentCtx, token, evt, body)

	case ctap2.CmdCredentialManagement, ctap2.CmdCredentialManagementPreview:
		s.handleCredentialManagement(parentCtx, token, evt, body)

	case ctap2.CmdClientPIN:
		s.handleClientPIN(parentCtx, token, evt, body)

	default:
		log.Printf("unrecognized CTAP2 command: 0x%02x", cmd)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidCommand)
	}
}

func (s *server) handleMakeCredential(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, body []byte) {
	req, err := ctap2.DecodeMakeCredentialRequest(body)
	if err != nil {
		log.Printf("decode makeCredential request err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	log.Printf("got CTAP2 MakeCredential site=%s rk=%v user=%s", req.RP.ID, req.ResidentKey, req.User.Name)

	if len(req.ExcludeList) > 0 {
		existing := s.resident.ByRPID(req.RP.ID)
		for _, excludeID := range req.ExcludeList {
			for _, cred := range existing {
				if string(cred.CredentialID) == string(excludeID) {
					log.Printf("credential excluded for site=%s (already registered)", req.RP.ID)
					token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusCredentialExcluded)
					return
				}
			}
		}
	}

	var challengeParam, applicationParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	rpIDHash := sha256.Sum256([]byte(req.RP.ID))
	copy(applicationParam[:], rpIDHash[:])

	pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Register", challengeParam, applicationParam)
	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("got pinentry result err: %s", result.Error)
			}
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
			return
		}
		log.Printf("pinentry confirmed for MakeCredential site=%s", req.RP.ID)
	case <-ctx.Done():
		log.Printf("pinentry timed out (30s) for MakeCredential site=%s", req.RP.ID)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	keyHandle, x, y, err := s.signer.RegisterKey(rpIDHash[:])
	if err != nil {
		log.Printf("RegisterKey err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}
	if len(keyHandle) > 1023 {
		log.Printf("keyHandle too large: %d", len(keyHandle))
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	// credentialId doubles as the opaque keyHandle: SignASN1 accepts it
	// directly, same as the U2F register/authenticate path.
	credID := keyHandle

	pubKeyX := x.Bytes()
	pubKeyY := y.Bytes()

	authData, err := ctap2.BuildAuthData(req.RP.ID, true, true, s.signer.Counter(), credID, pubKeyX, pubKeyY)
	if err != nil {
		log.Printf("BuildAuthData err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	toSign := append(append([]byte{}, authData...), req.ClientDataHash...)
	sigHash := sha256.Sum256(toSign)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sigHash[:])
	if err != nil {
		log.Printf("attestation sign err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	resp, err := ctap2.EncodeMakeCredentialResponse(authData, sig, attestation.CertDer)
	if err != nil {
		log.Printf("EncodeMakeCredentialResponse err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	if req.ResidentKey {
		cred := residentstore.Credential{
			CredentialID: credID,
			RPID:         req.RP.ID,
			UserID:       req.User.ID,
			UserName:     req.User.Name,
			KeyHandle:    keyHandle,
		}
		if err := s.resident.Put(cred); err != nil {
			log.Printf("persist resident credential err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
	}

	if err := token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess); err != nil {
		log.Printf("write makeCredential response err: %s", err)
	}
}

func (s *server) handleGetAssertion(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, body []byte) {
	req, err := ctap2.DecodeGetAssertionRequest(body)
	if err != nil {
		log.Printf("decode getAssertion request err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	log.Printf("got CTAP2 GetAssertion site=%s allowList=%d", req.RPID, len(req.AllowList))

	var credID []byte
	var userID []byte
	var userName string

	if len(req.AllowList) > 0 {
		// Non-discoverable flow: the RP already told us which credential
		// to use, so we don't need the resident store at all.
		credID = req.AllowList[0]
	} else {
		// Discoverable flow: look up resident credentials for this rpId.
		// If multiple accounts are registered for the same rpId, we always
		// pick the most recently created one rather than returning
		// numberOfCredentials>1 and letting the client prompt an account
		// picker; simpler, and fine for a personal-use authenticator, but
		// a deviation from the full multi-account CTAP2 flow.
		creds := s.resident.ByRPID(req.RPID)
		if len(creds) == 0 {
			log.Printf("no resident credentials for rpId=%s", req.RPID)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		cred := creds[len(creds)-1]
		credID = cred.CredentialID
		userID = cred.UserID
		userName = cred.UserName
	}

	rpIDHash := sha256.Sum256([]byte(req.RPID))

	userVerified := false

	if req.UserPresence {
		var challengeParam, applicationParam [32]byte
		copy(challengeParam[:], req.ClientDataHash)
		copy(applicationParam[:], rpIDHash[:])

		pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Auth", challengeParam, applicationParam)
		if err != nil {
			log.Printf("pinentry err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
			return
		}

		ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if !result.OK {
				if result.Error != nil {
					log.Printf("got pinentry result err: %s", result.Error)
				}
				token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
				return
			}
			userVerified = true
		case <-ctx.Done():
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
			return
		}
	} else {
		log.Printf("silent GetAssertion (up=false) for site=%s, skipping pinentry", req.RPID)
	}

	// Resident credentials get their own persisted, monotonic per-credential
	// counter (as CTAP2 intends); non-resident (allowList) credentials fall
	// back to the device-wide wall-clock counter, since we have no record
	// of them to track a counter against.
	var signCount uint32
	if len(userID) > 0 {
		signCount, err = s.resident.IncrementSignCount(req.RPID, credID)
		if err != nil {
			log.Printf("increment sign count err: %s", err)
			signCount = s.signer.Counter()
		}
	} else {
		signCount = s.signer.Counter()
	}

	authData, err := ctap2.BuildAuthData(req.RPID, req.UserPresence, userVerified, signCount, nil, nil, nil)
	if err != nil {
		log.Printf("BuildAuthData err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	toSign := append(append([]byte{}, authData...), req.ClientDataHash...)
	sigHash := sha256.Sum256(toSign)

	sig, err := s.signer.SignASN1(credID, rpIDHash[:], sigHash[:])
	if err != nil {
		log.Printf("sign err: %s (credID size: %d)", err, len(credID))
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidCredential)
		return
	}

	resp, err := ctap2.EncodeGetAssertionResponse(credID, authData, sig, userID, userName)
	if err != nil {
		log.Printf("EncodeGetAssertionResponse err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	if err := token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess); err != nil {
		log.Printf("write getAssertion response err: %s", err)
	}
}

// handleCredentialManagement implements the read/delete subset of
// authenticatorCredentialManagement (CTAP 2.1 §6.8): getCredsMetadata,
// enumerateRPsBegin/GetNextRP, enumerateCredentialsBegin/GetNextCredential,
// and deleteCredential. Per spec, the "Begin"/metadata/delete subcommands
// require a valid pinUvAuthParam proving possession of a pinUvAuthToken
// obtained via authenticatorClientPIN/getPINToken; the GetNext* pagination
// calls do not re-authenticate since they continue an already-authenticated
// enumeration.
func (s *server) handleCredentialManagement(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, body []byte) {
	req, err := ctap2.DecodeCredentialManagementRequest(body)
	if err != nil {
		log.Printf("decode credentialManagement request err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	switch req.SubCommand {
	case ctap2.CredMgmtSubGetCredsMetadata, ctap2.CredMgmtSubEnumerateRPsBegin,
		ctap2.CredMgmtSubEnumerateCredsBegin, ctap2.CredMgmtSubDeleteCredential:
		if !s.verifyPinToken(req.AuthenticatedMessage, req.PinUvAuthParam) {
			log.Printf("credentialManagement subcommand 0x%02x: invalid or missing pinUvAuthParam", req.SubCommand)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
			return
		}
	}

	switch req.SubCommand {
	case ctap2.CredMgmtSubGetCredsMetadata:
		resp, err := ctap2.EncodeGetCredsMetadataResponse(s.resident.Count())
		if err != nil {
			log.Printf("EncodeGetCredsMetadataResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubEnumerateRPsBegin:
		s.credMgmtCursor = credMgmtCursor{rpIDs: s.resident.RPIDs()}
		if len(s.credMgmtCursor.rpIDs) == 0 {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		rpID := s.credMgmtCursor.rpIDs[0]
		s.credMgmtCursor.rpIdx = 1
		resp, err := ctap2.EncodeEnumerateRPResponse(rpID, len(s.credMgmtCursor.rpIDs), true)
		if err != nil {
			log.Printf("EncodeEnumerateRPResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubEnumerateRPsGetNextRP:
		if s.credMgmtCursor.rpIdx >= len(s.credMgmtCursor.rpIDs) {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		rpID := s.credMgmtCursor.rpIDs[s.credMgmtCursor.rpIdx]
		s.credMgmtCursor.rpIdx++
		resp, err := ctap2.EncodeEnumerateRPResponse(rpID, 0, false)
		if err != nil {
			log.Printf("EncodeEnumerateRPResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubEnumerateCredsBegin:
		if len(req.RPIDHash) == 0 {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		rpID := s.rpIDForHash(req.RPIDHash)
		creds := s.resident.ByRPID(rpID)
		if len(creds) == 0 {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		s.credMgmtCursor.creds = creds
		s.credMgmtCursor.credIdx = 1
		resp, err := ctap2.EncodeEnumerateCredentialResponse(creds[0].CredentialID, creds[0].UserID, creds[0].UserName, len(creds), true)
		if err != nil {
			log.Printf("EncodeEnumerateCredentialResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubEnumerateCredsGetNextCred:
		if s.credMgmtCursor.credIdx >= len(s.credMgmtCursor.creds) {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		cred := s.credMgmtCursor.creds[s.credMgmtCursor.credIdx]
		s.credMgmtCursor.credIdx++
		resp, err := ctap2.EncodeEnumerateCredentialResponse(cred.CredentialID, cred.UserID, cred.UserName, 0, false)
		if err != nil {
			log.Printf("EncodeEnumerateCredentialResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubDeleteCredential:
		if len(req.CredID) == 0 {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}

		rpID := s.rpIDForCredential(req.CredID)
		if rpID == "" {
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidCredential)
			return
		}

		// pinUvAuthParam verification above already proves possession of
		// a valid pinUvAuthToken obtained via a PIN the user entered, so
		// no separate pinentry presence prompt is needed here -- the PIN
		// entry itself was the authorization step, same as how deleting a
		// resident credential works on real security keys.
		if err := s.resident.Delete(rpID, req.CredID); err != nil {
			log.Printf("delete credential err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidCredential)
			return
		}
		log.Printf("deleted resident credential for rpId=%s", rpID)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusSuccess)

	default:
		log.Printf("unsupported credentialManagement subcommand: 0x%02x", req.SubCommand)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusUnsupportedOption)
	}
}

// rpIDForHash finds the rpId whose sha256 hash matches rpIDHash, by
// checking against every rpId currently in the resident store. The store
// indexes by plaintext rpId (not hash), so this is a linear scan; fine at
// the scale of a personal authenticator's credential count.
func (s *server) rpIDForHash(rpIDHash []byte) string {
	for _, rpID := range s.resident.RPIDs() {
		h := sha256.Sum256([]byte(rpID))
		if string(h[:]) == string(rpIDHash) {
			return rpID
		}
	}
	return ""
}

// rpIDForCredential finds which rpId a given credentialId belongs to.
func (s *server) rpIDForCredential(credID []byte) string {
	for _, rpID := range s.resident.RPIDs() {
		for _, cred := range s.resident.ByRPID(rpID) {
			if string(cred.CredentialID) == string(credID) {
				return rpID
			}
		}
	}
	return ""
}

// handleClientPIN implements the subset of authenticatorClientPIN (PIN/UV
// Auth Protocol One) needed for CTAP2 clients like libfido2 to obtain a
// pinUvAuthToken and use it for credential management: getKeyAgreement,
// setPIN, changePIN, getPINToken. The PIN itself never touches disk or
// pinentry -- only its hash (via the platform-computed pinHashEnc) is ever
// seen, and only in memory during verification.
func (s *server) handleClientPIN(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, body []byte) {
	req, err := ctap2.DecodeClientPINRequest(body)
	if err != nil {
		log.Printf("decode clientPIN request err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	switch req.SubCommand {
	case ctap2.ClientPINSubGetKeyAgreement:
		x, y := s.keyAgreement.PublicKeyXY()
		resp, err := ctap2.EncodeClientPINKeyAgreementResponse(x, y)
		if err != nil {
			log.Printf("EncodeClientPINKeyAgreementResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.ClientPINSubSetPIN:
		s.handleSetPIN(parentCtx, token, evt, req)

	case ctap2.ClientPINSubChangePIN:
		s.handleChangePIN(parentCtx, token, evt, req)

	case ctap2.ClientPINSubGetPINToken:
		s.handleGetPINToken(parentCtx, token, evt, req)

	default:
		log.Printf("unsupported clientPIN subcommand: 0x%02x", req.SubCommand)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusUnsupportedOption)
	}
}

func (s *server) handleSetPIN(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, req *ctap2.ClientPINRequest) {
	if s.pins.IsSet() {
		// setPIN is only valid when no PIN exists yet; changePIN is used
		// after that. Real authenticators reject this as PIN_AUTH_INVALID.
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	_, newPin, ok := s.decryptNewPIN(token, parentCtx, evt, req)
	if !ok {
		return
	}

	if err := s.pins.SetPIN(pinprotocol.HashPIN(newPin)); err != nil {
		log.Printf("SetPIN err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	log.Printf("PIN set")
	token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusSuccess)
}

func (s *server) handleChangePIN(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, req *ctap2.ClientPINRequest) {
	if !s.pins.IsSet() {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	sharedSecret, err := s.keyAgreement.SharedSecret(req.PeerKeyX, req.PeerKeyY)
	if err != nil {
		log.Printf("SharedSecret err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	if len(req.PinHashEnc) == 0 || len(req.NewPinEnc) == 0 || len(req.PinUvAuthParam) == 0 {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	// pinUvAuthParam for changePIN is computed over newPinEnc||pinHashEnc.
	msg := append(append([]byte{}, req.NewPinEnc...), req.PinHashEnc...)
	if !pinprotocol.VerifyAuthenticate(sharedSecret, msg, req.PinUvAuthParam) {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	pinHash, err := pinprotocol.Decrypt(sharedSecret, req.PinHashEnc)
	if err != nil {
		log.Printf("decrypt pinHashEnc err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	match, err := s.pins.Verify(pinHash)
	if err != nil {
		log.Printf("PIN locked out: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}
	if !match {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	newPinPadded, err := pinprotocol.Decrypt(sharedSecret, req.NewPinEnc)
	if err != nil {
		log.Printf("decrypt newPinEnc err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}
	newPin := trimPINPadding(newPinPadded)

	if err := s.pins.SetPIN(pinprotocol.HashPIN(newPin)); err != nil {
		log.Printf("SetPIN err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	// Any previously issued token is invalidated by a PIN change.
	s.pinToken = nil

	log.Printf("PIN changed")
	token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusSuccess)
}

func (s *server) handleGetPINToken(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, req *ctap2.ClientPINRequest) {
	if !s.pins.IsSet() {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	sharedSecret, err := s.keyAgreement.SharedSecret(req.PeerKeyX, req.PeerKeyY)
	if err != nil {
		log.Printf("SharedSecret err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	if len(req.PinHashEnc) == 0 {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	pinHash, err := pinprotocol.Decrypt(sharedSecret, req.PinHashEnc)
	if err != nil {
		log.Printf("decrypt pinHashEnc err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	match, err := s.pins.Verify(pinHash)
	if err != nil {
		log.Printf("PIN locked out: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}
	if !match {
		log.Printf("PIN mismatch, %d retries left", s.pins.RetriesLeft())
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	pinToken := make([]byte, 32)
	if _, err := rand.Read(pinToken); err != nil {
		log.Printf("generate pinToken err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}
	s.pinToken = pinToken

	encryptedToken, err := pinprotocol.Encrypt(sharedSecret, pinToken)
	if err != nil {
		log.Printf("encrypt pinToken err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	resp, err := ctap2.EncodeClientPINTokenResponse(encryptedToken)
	if err != nil {
		log.Printf("EncodeClientPINTokenResponse err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	log.Printf("issued pinUvAuthToken")
	token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)
}

// decryptNewPIN validates and decrypts the newPinEnc field for setPIN,
// verifying pinUvAuthParam (computed over newPinEnc alone, unlike
// changePIN which includes pinHashEnc too) and stripping the zero padding
// PIN plaintexts are padded to a 64-byte boundary with.
func (s *server) decryptNewPIN(token *fidohid.SoftToken, parentCtx context.Context, evt fidohid.AuthEvent, req *ctap2.ClientPINRequest) ([]byte, string, bool) {
	sharedSecret, err := s.keyAgreement.SharedSecret(req.PeerKeyX, req.PeerKeyY)
	if err != nil {
		log.Printf("SharedSecret err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return nil, "", false
	}

	if len(req.NewPinEnc) == 0 || len(req.PinUvAuthParam) == 0 {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return nil, "", false
	}

	if !pinprotocol.VerifyAuthenticate(sharedSecret, req.NewPinEnc, req.PinUvAuthParam) {
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return nil, "", false
	}

	newPinPadded, err := pinprotocol.Decrypt(sharedSecret, req.NewPinEnc)
	if err != nil {
		log.Printf("decrypt newPinEnc err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return nil, "", false
	}

	return sharedSecret, trimPINPadding(newPinPadded), true
}

// trimPINPadding strips the trailing zero-byte padding CTAP2 platforms pad
// newPinEnc plaintext to (64 bytes for Protocol One).
func trimPINPadding(padded []byte) string {
	i := len(padded)
	for i > 0 && padded[i-1] == 0 {
		i--
	}
	return string(padded[:i])
}

// verifyPinToken checks pinUvAuthParam against the current pinUvAuthToken
// for a privileged (token-gated) request, using constant-time comparison
// on the derived HMAC to avoid a timing oracle.
func (s *server) verifyPinToken(message, pinUvAuthParam []byte) bool {
	if len(s.pinToken) == 0 || len(pinUvAuthParam) == 0 {
		return false
	}
	expected := pinprotocol.Authenticate(s.pinToken, message)
	return subtle.ConstantTimeCompare(expected, pinUvAuthParam) == 1
}
