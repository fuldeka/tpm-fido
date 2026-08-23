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
	"github.com/psanford/tpm-fido/uvmethod"
)

func (s *server) handleCbor(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	s.cborRateLimit.Wait()

	if len(evt.Cbor) == 0 {
		log.Printf("empty cbor message")
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	cmd := evt.Cbor[0]
	body := evt.Cbor[1:]

	switch cmd {
	case ctap2.CmdGetInfo:
		internalUV := s.uvcfg.InternalUV()
		log.Printf("got CTAP2 authenticatorGetInfo (internalUV=%t)", internalUV)
		resp, err := ctap2.EncodeGetInfoResponse(s.pins.IsSet(), internalUV)
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

	if req.ResidentKey && len(req.User.ID) == 0 {
		// residentstore.Put keys credentials by rpId+userId; an empty
		// userId would collide with (and silently clobber) any other
		// resident credential at the same RP that also has an empty
		// userId, discarding that user's credential.
		log.Printf("rejecting resident MakeCredential with empty user.id site=%s", req.RP.ID)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusMissingParameter)
		return
	}

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

	// The platform signals it wants user verification in one of two ways:
	// the legacy options.uv boolean (req.UserVerification), or -- what
	// real CTAP2 platforms (Chrome, Firefox) actually send -- by
	// including pinUvAuthParam directly, having already gone through
	// clientPIN/getPINToken, without necessarily also setting options.uv.
	// Gating this purely on req.UserVerification (as an earlier version
	// of this code did) meant a platform that only sent pinUvAuthParam
	// was silently treated as not requiring UV: the pinUvAuthParam was
	// simply ignored, MakeCredential proceeded as presence-only, and the
	// resulting authData had UV=0 even though the platform did everything
	// right and the RP required uv:"required". So: verify pinUvAuthParam
	// whenever it's present, regardless of options.uv; only treat
	// options.uv=true with no param as the "go get a token" case.
	userVerified := false
	if len(req.PinUvAuthParam) > 0 {
		if req.PinUvAuthProtocol != 1 {
			log.Printf("MakeCredential site=%s: unsupported pinUvAuthProtocol %d", req.RP.ID, req.PinUvAuthProtocol)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidParameter)
			return
		}
		if !s.verifyPinToken(req.ClientDataHash, req.PinUvAuthParam) {
			log.Printf("MakeCredential site=%s: pinUvAuthParam did not verify", req.RP.ID)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusPinAuthInvalid)
			return
		}
		userVerified = true
	} else if req.UserVerification {
		// Distinct from an invalid param: this tells the platform a
		// pinUvAuthToken is needed so it goes and gets one via
		// clientPIN/getPINToken, rather than (as StatusOperationDenied
		// would suggest) blindly retrying the exact same request.
		log.Printf("MakeCredential site=%s: uv required, no pinUvAuthParam supplied", req.RP.ID)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusPinRequired)
		return
	}

	var challengeParam, applicationParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	rpIDHash := sha256.Sum256([]byte(req.RP.ID))
	copy(applicationParam[:], rpIDHash[:])

	pinResultCh, err := s.pe.ConfirmPresence(parentCtx, "FIDO Confirm Register", challengeParam, applicationParam)
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
		if parentCtx.Err() != nil {
			log.Printf("MakeCredential canceled by platform for site=%s", req.RP.ID)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusKeepAliveCancel)
			return
		}
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

	// userVerified reflects an actual pinUvAuthParam check above, not just
	// the pinentry presence tap -- UV must never be reported true unless a
	// PIN was genuinely verified for this request.
	authData, err := ctap2.BuildAuthData(req.RP.ID, true, userVerified, ctap2.InitialSignCount, credID, pubKeyX, pubKeyY)
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

	rpIDHash := sha256.Sum256([]byte(req.RPID))

	var credID []byte
	var userID []byte
	var userName string

	if len(req.AllowList) > 0 {
		// Non-discoverable flow: the RP handed us one or more candidate
		// credential IDs (e.g. from stored credentials for multiple
		// authenticators); only one of them is ours. Probe each with a
		// dummy signature -- same technique handleAuthenticate uses for
		// the U2F path -- and use the first one this signer recognizes,
		// rather than blindly assuming AllowList[0] is ours.
		dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
		for _, cand := range req.AllowList {
			if _, err := s.signer.SignASN1(cand, rpIDHash[:], dummySig[:]); err == nil {
				credID = cand
				break
			}
		}
		if credID == nil {
			log.Printf("no allowList credential recognized for site=%s", req.RPID)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
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

	// userVerified reflects an actual pinUvAuthParam check against the
	// current pinToken, never the pinentry presence tap below -- a tap
	// only proves presence, not that the user's PIN was verified. Verify
	// pinUvAuthParam whenever the platform sent one, regardless of
	// options.uv -- real platforms signal UV intent by sending the param,
	// not necessarily by also setting options.uv (see the longer comment
	// in handleMakeCredential for why gating on options.uv alone is
	// wrong).
	userVerified := false
	if len(req.PinUvAuthParam) > 0 {
		if req.PinUvAuthProtocol != 1 {
			log.Printf("GetAssertion site=%s: unsupported pinUvAuthProtocol %d", req.RPID, req.PinUvAuthProtocol)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidParameter)
			return
		}
		if !s.verifyPinToken(req.ClientDataHash, req.PinUvAuthParam) {
			log.Printf("GetAssertion site=%s: pinUvAuthParam did not verify", req.RPID)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusPinAuthInvalid)
			return
		}
		userVerified = true
	} else if req.UserVerification {
		log.Printf("GetAssertion site=%s: uv required, no pinUvAuthParam supplied", req.RPID)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusPinRequired)
		return
	}

	if req.UserPresence {
		var challengeParam, applicationParam [32]byte
		copy(challengeParam[:], req.ClientDataHash)
		copy(applicationParam[:], rpIDHash[:])

		pinResultCh, err := s.pe.ConfirmPresence(parentCtx, "FIDO Confirm Auth", challengeParam, applicationParam)
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
		case <-ctx.Done():
			if parentCtx.Err() != nil {
				log.Printf("GetAssertion canceled by platform for site=%s", req.RPID)
				token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusKeepAliveCancel)
				return
			}
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
		if req.PinUvAuthProtocol != 1 {
			log.Printf("credentialManagement subcommand 0x%02x: unsupported pinUvAuthProtocol %d", req.SubCommand, req.PinUvAuthProtocol)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidParameter)
			return
		}
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
		s.credMgmtCursorMu.Lock()
		s.credMgmtCursor = credMgmtCursor{rpIDs: s.resident.RPIDs()}
		if len(s.credMgmtCursor.rpIDs) == 0 {
			s.credMgmtCursorMu.Unlock()
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		rpID := s.credMgmtCursor.rpIDs[0]
		total := len(s.credMgmtCursor.rpIDs)
		s.credMgmtCursor.rpIdx = 1
		s.credMgmtCursorMu.Unlock()
		resp, err := ctap2.EncodeEnumerateRPResponse(rpID, total, true)
		if err != nil {
			log.Printf("EncodeEnumerateRPResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubEnumerateRPsGetNextRP:
		s.credMgmtCursorMu.Lock()
		if s.credMgmtCursor.rpIdx >= len(s.credMgmtCursor.rpIDs) {
			s.credMgmtCursorMu.Unlock()
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		rpID := s.credMgmtCursor.rpIDs[s.credMgmtCursor.rpIdx]
		s.credMgmtCursor.rpIdx++
		s.credMgmtCursorMu.Unlock()
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
		s.credMgmtCursorMu.Lock()
		s.credMgmtCursor.creds = creds
		s.credMgmtCursor.credIdx = 1
		s.credMgmtCursorMu.Unlock()
		resp, err := ctap2.EncodeEnumerateCredentialResponse(creds[0].CredentialID, creds[0].UserID, creds[0].UserName, len(creds), true)
		if err != nil {
			log.Printf("EncodeEnumerateCredentialResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.CredMgmtSubEnumerateCredsGetNextCred:
		s.credMgmtCursorMu.Lock()
		if s.credMgmtCursor.credIdx >= len(s.credMgmtCursor.creds) {
			s.credMgmtCursorMu.Unlock()
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusNoCredentials)
			return
		}
		cred := s.credMgmtCursor.creds[s.credMgmtCursor.credIdx]
		s.credMgmtCursor.credIdx++
		s.credMgmtCursorMu.Unlock()
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
// Auth Protocol One) needed for CTAP2 clients like libfido2 and Chrome to
// obtain a pinUvAuthToken and use it for credential management:
// getPINRetries, getKeyAgreement, setPIN, changePIN, getPINToken. The PIN
// itself never touches disk or pinentry -- only its hash (via the
// platform-computed pinHashEnc) is ever seen, and only in memory during
// verification.
func (s *server) handleClientPIN(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, body []byte) {
	req, err := ctap2.DecodeClientPINRequest(body)
	if err != nil {
		log.Printf("decode clientPIN request err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	switch req.SubCommand {
	case ctap2.ClientPINSubSetPIN, ctap2.ClientPINSubChangePIN,
		ctap2.ClientPINSubGetPINToken, ctap2.ClientPINSubGetPinUvAuthTokenUsingPIN:
		if req.PinUvAuthProtocol != 1 {
			log.Printf("clientPIN subcommand 0x%02x: unsupported pinUvAuthProtocol %d", req.SubCommand, req.PinUvAuthProtocol)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusInvalidParameter)
			return
		}
	}

	switch req.SubCommand {
	case ctap2.ClientPINSubGetPINRetries:
		resp, err := ctap2.EncodeClientPINRetriesResponse(s.pins.RetriesLeft())
		if err != nil {
			log.Printf("EncodeClientPINRetriesResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

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

	case ctap2.ClientPINSubGetPINToken, ctap2.ClientPINSubGetPinUvAuthTokenUsingPIN:
		s.handleGetPINToken(parentCtx, token, evt, req)

	case ctap2.ClientPINSubGetUVRetries:
		resp, err := ctap2.EncodeClientPINUVRetriesResponse(s.pins.RetriesLeft())
		if err != nil {
			log.Printf("EncodeClientPINUVRetriesResponse err: %s", err)
			token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
			return
		}
		token.WriteCborResponse(parentCtx, evt, resp, ctap2.StatusSuccess)

	case ctap2.ClientPINSubGetUvToken:
		s.handleGetUvToken(parentCtx, token, evt, req)

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
	s.setPinToken(nil)

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
	s.setPinToken(pinToken)

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

// handleGetUvToken implements CTAP 2.1
// getPinUvAuthTokenUsingUvWithPermissions (subcommand 0x06): the
// Windows-Hello-style path. Instead of the platform sending us a
// browser-collected pinHashEnc, WE perform built-in user verification on our
// own side (via s.uvVerifier -- a system PIN dialog today, potentially
// biometrics later) and, on success, mint a UV-backed pinUvAuthToken. The
// browser never shows a PIN box.
//
// This is only reachable when getInfo advertised uv:true, which is gated on
// the internal-UV toggle plus a PIN being set; we re-check the toggle here as
// defense-in-depth in case it was flipped off between getInfo and this call.
func (s *server) handleGetUvToken(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent, req *ctap2.ClientPINRequest) {
	if !s.uvcfg.InternalUV() || !s.pins.IsSet() {
		log.Printf("getUvToken refused: internal UV not enabled")
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusUnsupportedOption)
		return
	}

	sharedSecret, err := s.keyAgreement.SharedSecret(req.PeerKeyX, req.PeerKeyY)
	if err != nil {
		log.Printf("SharedSecret err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	// Built-in user verification (our own system prompt). This blocks on the
	// user; parentCtx cancellation (CTAPHID_CANCEL) aborts it.
	outcome, err := s.uvVerifier.Verify(parentCtx, req.RpID)
	if err != nil {
		log.Printf("getUvToken: uv method %q error: %s", s.uvVerifier.Name(), err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	switch outcome {
	case uvmethod.Verified:
		// fall through to mint the token
	case uvmethod.LockedOut:
		log.Printf("getUvToken: uv method %q locked out", s.uvVerifier.Name())
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusPinBlocked)
		return
	case uvmethod.Unavailable:
		log.Printf("getUvToken: uv method %q unavailable", s.uvVerifier.Name())
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusUnsupportedOption)
		return
	default: // Rejected
		log.Printf("getUvToken: user verification declined/failed")
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOperationDenied)
		return
	}

	uvToken := make([]byte, 32)
	if _, err := rand.Read(uvToken); err != nil {
		log.Printf("generate uvToken err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}
	s.setPinToken(uvToken)

	encryptedToken, err := pinprotocol.Encrypt(sharedSecret, uvToken)
	if err != nil {
		log.Printf("encrypt uvToken err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	resp, err := ctap2.EncodeClientPINTokenResponse(encryptedToken)
	if err != nil {
		log.Printf("EncodeClientPINTokenResponse err: %s", err)
		token.WriteCborResponse(parentCtx, evt, nil, ctap2.StatusOther)
		return
	}

	log.Printf("issued UV-backed pinUvAuthToken (no browser PIN box)")
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
	tok := s.getPinToken()
	if len(tok) == 0 || len(pinUvAuthParam) == 0 {
		return false
	}
	expected := pinprotocol.Authenticate(tok, message)
	return subtle.ConstantTimeCompare(expected, pinUvAuthParam) == 1
}
