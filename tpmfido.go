package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"log"
	"math/big"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/psanford/tpm-fido/attestation"
	"github.com/psanford/tpm-fido/ctlsocket"
	"github.com/psanford/tpm-fido/fidoauth"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/memory"
	"github.com/psanford/tpm-fido/pinentry"
	"github.com/psanford/tpm-fido/pinprotocol"
	"github.com/psanford/tpm-fido/pinstore"
	"github.com/psanford/tpm-fido/residentstore"
	"github.com/psanford/tpm-fido/sitesignatures"
	"github.com/psanford/tpm-fido/statuscode"
	"github.com/psanford/tpm-fido/tpm"
	"github.com/psanford/tpm-fido/uvconfig"
	"github.com/psanford/tpm-fido/uvmethod"
	"github.com/psanford/tpm-fido/uvmethod/pinverifier"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var residentStorePath = flag.String("resident-store", "", "path to resident (discoverable) credential metadata store; defaults to $XDG_CONFIG_HOME/tpm-fido/resident-credentials.json")
var pinStorePath = flag.String("pin-store", "", "path to PIN hash/retry-counter store; defaults to $XDG_CONFIG_HOME/tpm-fido/pin-state.json")
var ctlSocketPath = flag.String("ctl-socket", "", "path to the local control-socket used by companion tools (e.g. a tray app); defaults to $XDG_RUNTIME_DIR/tpm-fido.sock")
var uvConfigPath = flag.String("uv-config", "", "path to the user-toggle store (internal-UV/Hello mode); defaults to $XDG_CONFIG_HOME/tpm-fido/uv-config.json")
var noTray = flag.Bool("no-tray", false, "don't launch the tpm-fido-tray companion UI (it's launched by default once tpm-fido-tray is found on PATH)")

func main() {
	flag.Parse()
	if err := acquireSingleInstanceLock(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	s := newServer()
	s.run()
}

type server struct {
	pe       *pinentry.Pinentry
	signer   Signer
	resident *residentstore.Store
	pins     *pinstore.Store

	// uvcfg holds user toggles, notably internal-UV ("Hello mode"). Read on
	// every getInfo so the tray can flip it live.
	uvcfg *uvconfig.Store

	// uvVerifier performs built-in user verification for the CTAP 2.1
	// internal-UV (getUvToken) path. PIN-backed today; the interface lets a
	// biometric backend replace it later without touching the CTAP2 layer.
	uvVerifier uvmethod.Verifier

	// credMgmtCursor holds pagination state for the CTAP2 credential
	// management enumerateRPs/enumerateCredentials GetNext* calls, which
	// are stateful across a sequence of CTAPHID requests on the same
	// channel. Each HID event is handled on its own goroutine (see
	// run()), so credMgmtCursorMu guards against concurrent enumeration
	// sessions racing on this single global cursor.
	credMgmtCursorMu sync.Mutex
	credMgmtCursor   credMgmtCursor

	// keyAgreement is this authenticator's ECDH keypair for CTAP2 PIN/UV
	// Auth Protocol One. Generated once at process start and reused for
	// every getKeyAgreement call, matching how real authenticators behave
	// for Protocol One (Protocol Two regenerates per call; not implemented
	// here).
	keyAgreement *pinprotocol.KeyAgreement

	// cborRateLimit gates handleCbor: a platform that spins on retrying a
	// rejected request (e.g. not implementing the clientPIN dance for
	// uv:required, so it just resends the same failing MakeCredential
	// forever) would otherwise burn CPU and flood the log at whatever
	// rate the HID transport can carry frames. Real CTAP2 traffic is
	// human-paced -- one operation per user action -- so this floor is
	// invisible in normal use.
	cborRateLimit *rateLimiter

	// pinToken is the current pinUvAuthToken, minted fresh on each
	// successful getPINToken exchange and required (as a valid HMAC key
	// over the request) for privileged operations. Cleared to nil on
	// process start; a real PIN entry is required after every restart.
	// Guarded by pinTokenMu since it's read/written from both the main
	// CTAP2/HID loop goroutine and the ctlsocket connection goroutines
	// (ChangePIN invalidates it from the latter).
	pinTokenMu sync.Mutex
	pinToken   []byte

	// lastPresence caches a recent successful presence tap so back-to-back
	// ceremonies (register -> auto-login) don't each demand their own click.
	// Deliberately global: within the window, any RP benefits.
	lastPresenceMu sync.Mutex
	lastPresence   time.Time
}

func (s *server) setPinToken(tok []byte) {
	s.pinTokenMu.Lock()
	s.pinToken = tok
	s.pinTokenMu.Unlock()
}

func (s *server) getPinToken() []byte {
	s.pinTokenMu.Lock()
	defer s.pinTokenMu.Unlock()
	return s.pinToken
}

type credMgmtCursor struct {
	rpIDs   []string
	rpIdx   int
	creds   []residentstore.Credential
	credIdx int
}

type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
}

func newServer() *server {
	s := server{
		pe:            pinentry.New(),
		cborRateLimit: newRateLimiter(50 * time.Millisecond),
	}
	if *backend == "tpm" {
		signer, err := tpm.New(*device)
		if err != nil {
			panic(err)
		}
		s.signer = signer
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			panic(err)
		}
		s.signer = signer
	}

	resident, err := residentstore.Open(*residentStorePath)
	if err != nil {
		panic(err)
	}
	s.resident = resident

	pins, err := pinstore.Open(*pinStorePath)
	if err != nil {
		panic(err)
	}
	s.pins = pins

	ka, err := pinprotocol.NewKeyAgreement()
	if err != nil {
		panic(err)
	}
	s.keyAgreement = ka

	uvcfg, err := uvconfig.Open(*uvConfigPath)
	if err != nil {
		panic(err)
	}
	s.uvcfg = uvcfg

	s.uvVerifier = pinverifier.New(s.pe, s.pins)

	return &s
}

func (s *server) run() {
	ctx := context.Background()

	if pinentry.FindPinentryGUIPath() == "" {
		log.Printf("warning: no gui pinentry binary detected in PATH. tpm-fido may not work correctly without a gui based pinentry")
	}

	token, err := fidohid.New(ctx, "tpm-fido")
	if err != nil {
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	ctlSocketReady := make(chan struct{})
	go func() {
		if err := ctlsocket.Listen(*ctlSocketPath, s.handleCtlRequest, ctlSocketReady); err != nil {
			log.Printf("control socket error: %s", err)
		}
	}()

	if !*noTray {
		go launchTray(ctlSocketReady)
	}

	for evt := range token.Events() {
		if evt.Error != nil {
			log.Printf("got token error: %s", err)
			continue
		}

		// Each request gets its own goroutine and its own cancelable
		// context (evt.Ctx, canceled by fidohid.Run on a CTAPHID_CANCEL
		// for this channel) rather than being handled inline: a slow
		// request (waiting on pinentry) must not block reads of other
		// channels' requests, and in particular must not block the
		// CANCEL packet that's meant to abort it.
		evt := evt
		go func() {
			if evt.IsCbor() {
				s.handleCbor(evt.Ctx, token, evt)
				return
			}

			req := evt.Req

			if req.Command == fidoauth.CmdAuthenticate {
				log.Printf("got AuthenticateCmd site=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam))

				s.handleAuthenticate(evt.Ctx, token, evt)
			} else if req.Command == fidoauth.CmdRegister {
				log.Printf("got RegisterCmd site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
				s.handleRegister(evt.Ctx, token, evt)
			} else if req.Command == fidoauth.CmdVersion {
				log.Print("got VersionCmd")
				s.handleVersion(evt.Ctx, token, evt)
			} else {
				log.Printf("unsupported request type: 0x%02x\n", req.Command)
				// send a not supported error for any commands that we don't understand.
				// Browsers depend on this to detect what features the token supports
				// (i.e. the u2f backwards compatibility)
				token.WriteResponse(evt.Ctx, evt, nil, statuscode.ClaNotSupported)
			}
		}()
	}
}

func (s *server) handleVersion(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError)
}

func (s *server) handleAuthenticate(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]

	dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))

	_, err := s.signer.SignASN1(keyHandle, appParam, dummySig[:])
	if err != nil {
		log.Printf("invalid key: %s (key handle size: %d)", err, len(keyHandle))

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		log.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		// check if the provided key is known by the token
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == fidoauth.CtrlEnforeUserPresenceAndSign {

		pinResultCh, err := s.pe.ConfirmPresence(parentCtx, "FIDO Confirm Auth", req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam)

		if err != nil {
			log.Printf("pinentry err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)

			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					log.Printf("Got pinentry result err: %s", result.Error)
				}

				// Got user cancelation, we want to propagate that so the browser gives up.
				// This isn't normally supported by a key so there's no status code for this.
				// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					log.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	signCounter := s.signer.Counter()

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sig, err := s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()
	req := evt.Req

	pinResultCh, err := s.pe.ConfirmPresence(parentCtx, "FIDO Confirm Register", req.Register.ChallengeParam, req.Register.ApplicationParam)

	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("Got pinentry result err: %s", result.Error)
			}

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				log.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		s.registerSite(parentCtx, token, evt)
	case <-ctx.Done():
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		log.Printf("RegisteKey err: %s", err)
		return
	}

	if len(keyHandle) > 255 {
		log.Printf("Error: keyHandle too large: %d, max=255", len(keyHandle))
		return
	}

	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sum := sigHash.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		log.Fatalf("attestation sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}
}

// launchTray starts the tpm-fido-tray companion UI once the control socket
// is ready to accept connections (so its first PINStatus call doesn't race
// the daemon's own startup), if it's found on PATH. Not finding it is not
// an error -- the daemon is fully functional without the tray UI, which is
// an optional convenience for managing the PIN/credentials, and most
// installs of tpm-fido won't have built it.
func launchTray(ctlSocketReady <-chan struct{}) {
	trayPath, err := exec.LookPath("tpm-fido-tray")
	if err != nil {
		log.Printf("tpm-fido-tray not found on PATH, skipping companion UI (use -no-tray to silence this)")
		return
	}

	<-ctlSocketReady

	cmd := exec.Command(trayPath)
	if err := cmd.Start(); err != nil {
		log.Printf("failed to launch tpm-fido-tray: %s", err)
		return
	}

	// Reap the child when it exits so it doesn't linger as a zombie; the
	// daemon doesn't care about or depend on the tray's exit status.
	go cmd.Wait()
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

// rateLimiter enforces a minimum interval between successive calls to
// Wait, blocking (rather than dropping) callers that arrive too soon so a
// platform that spins on retrying a request is slowed to interval-paced
// instead of running as fast as the transport allows, without needing any
// per-request/per-channel bookkeeping.
type rateLimiter struct {
	interval time.Duration

	mu   sync.Mutex
	next time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{interval: interval}
}

func (r *rateLimiter) Wait() {
	r.mu.Lock()
	now := time.Now()
	wait := r.next.Sub(now)
	if wait < 0 {
		wait = 0
	}
	r.next = now.Add(wait).Add(r.interval)
	r.mu.Unlock()

	if wait > 0 {
		time.Sleep(wait)
	}
}
