package pinentry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

// ConfirmTimeout is how long the presence-confirm dialog waits for a
// click. Callers waiting on ConfirmPresence should use the same value so
// they never give up before the dialog closes.
const ConfirmTimeout = 30 * time.Second

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	extendTimeout chan time.Duration
	done          chan struct{}

	mu      sync.Mutex
	cancel  context.CancelFunc
	waiters []chan Result

	challengeParam   [32]byte
	applicationParam [32]byte
}

type Result struct {
	OK    bool
	Error error
	// PIN carries the entered PIN for CollectPIN requests. Empty for
	// ConfirmPresence (which only confirms presence, never collects a
	// secret). Callers must zero it after use.
	PIN string
}

// ConfirmPresence prompts the user via pinentry and returns a channel that
// receives the result. If callerCtx is canceled (e.g. the CTAP2 request that
// initiated this prompt received a CTAPHID_CANCEL) before the user responds,
// the pinentry subprocess is killed and the pending result resolves to
// OK:false, same as an explicit user cancel -- otherwise a canceled request
// would leave the dialog open on screen and its stale activeRequest entry
// would keep absorbing/extending unrelated later requests.
func (pe *Pinentry) ConfirmPresence(callerCtx context.Context, prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Generous window: this dialog is also the fallback consent prompt when
	// no PIN was verified, and missing it fails the whole ceremony.
	timeout := ConfirmTimeout

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		req := pe.activeRequest
		extendTimeoutChan := req.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
			}
		}()

		resultChan := make(chan Result, 1)
		req.mu.Lock()
		req.waiters = append(req.waiters, resultChan)
		req.mu.Unlock()

		go watchCancel(callerCtx, req, resultChan)

		return resultChan, nil
	}

	req := &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		extendTimeout:    make(chan time.Duration),
		done:             make(chan struct{}),
	}
	pe.activeRequest = req

	resultChan := make(chan Result, 1)
	req.waiters = append(req.waiters, resultChan)

	go pe.prompt(req, prompt)
	go watchCancel(callerCtx, req, resultChan)

	return resultChan, nil
}

// watchCancel resolves resultChan with a canceled/denied result if callerCtx
// is canceled before the request resolves on its own (result delivered or
// timed out). Only the caller that owns resultChan is affected -- other
// callers coalesced onto the same underlying pinentry prompt keep waiting.
// The shared pinentry subprocess itself is only killed once every waiter has
// been canceled, so one caller's CTAPHID_CANCEL never yanks the dialog out
// from under a still-live sibling request.
func watchCancel(callerCtx context.Context, req *request, resultChan chan Result) {
	select {
	case <-callerCtx.Done():
		req.mu.Lock()
		allCanceled := true
		for i, w := range req.waiters {
			if w == resultChan {
				req.waiters = append(req.waiters[:i], req.waiters[i+1:]...)
				break
			}
		}
		if len(req.waiters) > 0 {
			allCanceled = false
		}
		cancel := req.cancel
		req.mu.Unlock()

		select {
		case resultChan <- Result{OK: false, Error: errors.New("canceled")}:
		default:
		}

		if allCanceled && cancel != nil {
			cancel()
		}
	case <-req.done:
	}
}

// CollectPIN shows a pinentry password dialog (text entry, not a bare
// confirm) and returns the entered PIN via the result channel. It is used by
// the CTAP 2.1 internal-UV path (getUvToken): unlike ConfirmPresence, it
// collects a secret rather than confirming presence, so it never coalesces
// with other requests -- each getUvToken gets its own fresh dialog. The
// caller must zero Result.PIN after use.
//
// desc is shown in the dialog body; if callerCtx is canceled before the user
// responds, the dialog is torn down and the result resolves to OK:false.
func (pe *Pinentry) CollectPIN(callerCtx context.Context, desc string) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if pe.activeRequest != nil {
		return nil, errors.New("other request already in progress")
	}

	req := &request{
		// A human typing a PIN needs more than the 2s presence-tap window.
		timeout:       60 * time.Second,
		extendTimeout: make(chan time.Duration),
		done:          make(chan struct{}),
	}
	pe.activeRequest = req

	resultChan := make(chan Result, 1)
	req.waiters = append(req.waiters, resultChan)

	go pe.promptPIN(req, desc)
	go watchCancel(callerCtx, req, resultChan)

	return resultChan, nil
}

func (pe *Pinentry) promptPIN(req *request, desc string) {
	sendResult := func(r Result) {
		req.mu.Lock()
		waiters := req.waiters
		req.waiters = nil
		req.mu.Unlock()

		for _, w := range waiters {
			select {
			case w <- r:
			default:
			}
		}

		close(req.done)

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req.mu.Lock()
	req.cancel = cancel
	req.mu.Unlock()

	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		sendResult(Result{OK: false, Error: fmt.Errorf("failed to start pinentry: %w", err)})
		return
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	p.SetTitle("TPM-FIDO")
	p.SetPrompt("PIN")
	p.SetDesc(desc)

	type pinResult struct {
		pin string
		ok  bool
	}
	promptResult := make(chan pinResult, 1)

	go func() {
		pin, err := p.GetPIN()
		promptResult <- pinResult{pin: pin, ok: err == nil}
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case r := <-promptResult:
			sendResult(Result{OK: r.ok, PIN: r.pin})
			return
		case <-timer.C:
			sendResult(Result{OK: false, Error: errors.New("request timed out")})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}
}

func (pe *Pinentry) prompt(req *request, prompt string) {
	sendResult := func(r Result) {
		req.mu.Lock()
		waiters := req.waiters
		req.waiters = nil
		req.mu.Unlock()

		for _, w := range waiters {
			// buffered (cap 1) so this never blocks; a waiter that already
			// got a canceled result via watchCancel just drops the send.
			select {
			case w <- r:
			default:
			}
		}

		close(req.done)

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req.mu.Lock()
	req.cancel = cancel
	req.mu.Unlock()

	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		sendResult(Result{
			OK:    false,
			Error: fmt.Errorf("failed to start pinentry: %w", err),
		})
		return
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	p.SetTitle("TPM-FIDO")
	p.SetPrompt("TPM-FIDO")
	p.SetDesc(prompt)

	promptResult := make(chan bool)

	go func() {
		err := p.Confirm()
		promptResult <- err == nil
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case ok := <-promptResult:
			sendResult(Result{
				OK: ok,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}
}

func FindPinentryGUIPath() string {
	candidates := []string{
		"pinentry-gnome3",
		"pinentry-qt5",
		"pinentry-qt4",
		"pinentry-qt",
		"pinentry-gtk-2",
		"pinentry-x11",
		"pinentry-fltk",
	}
	for _, candidate := range candidates {
		p, _ := exec.LookPath(candidate)
		if p != "" {
			return p
		}
	}
	return ""
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	pinEntryCmd := FindPinentryGUIPath()
	if pinEntryCmd == "" {
		log.Printf("Failed to detect gui pinentry binary. Falling back to default `pinentry`")
		pinEntryCmd = "pinentry"
	}
	cmd := exec.CommandContext(ctx, pinEntryCmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var c pinentry.Client
	c.Session, err = assuan.Init(assuan.ReadWriteCloser{
		ReadCloser:  stdout,
		WriteCloser: stdin,
	})

	if err != nil {
		return nil, nil, err
	}
	return &c, cmd, nil
}
