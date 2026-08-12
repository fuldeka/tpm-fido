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

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration
	done          chan struct{}

	mu     sync.Mutex
	cancel context.CancelFunc

	challengeParam   [32]byte
	applicationParam [32]byte
}

type Result struct {
	OK    bool
	Error error
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

	timeout := 2 * time.Second

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := pe.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
			}
		}()

		go watchCancel(callerCtx, pe.activeRequest)

		return pe.activeRequest.pendingResult, nil
	}

	req := &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
		done:             make(chan struct{}),
	}
	pe.activeRequest = req

	go pe.prompt(req, prompt)
	go watchCancel(callerCtx, req)

	return req.pendingResult, nil
}

// watchCancel kills req's pinentry subprocess if callerCtx is canceled
// before the request resolves on its own (result delivered or timed out).
func watchCancel(callerCtx context.Context, req *request) {
	select {
	case <-callerCtx.Done():
		req.mu.Lock()
		cancel := req.cancel
		req.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	case <-req.done:
	}
}

func (pe *Pinentry) prompt(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(req.timeout):
			// we expect requests to come in every ~750ms.
			// If we've been waiting for 2 seconds the client
			// is likely gone.
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
