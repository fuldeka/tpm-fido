package pinentry

import (
	"context"
	"testing"
	"time"
)

func TestWatchCancelCallsCancelOnCallerCtxDone(t *testing.T) {
	callerCtx, callerCancel := context.WithCancel(context.Background())

	resultChan := make(chan Result, 1)
	req := &request{done: make(chan struct{}), waiters: []chan Result{resultChan}}
	called := make(chan struct{})
	req.cancel = func() { close(called) }

	go watchCancel(callerCtx, req, resultChan)

	callerCancel()

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("expected req.cancel to be called after callerCtx was canceled")
	}
}

func TestWatchCancelStopsOnRequestDoneWithoutCanceling(t *testing.T) {
	callerCtx := context.Background() // never canceled

	resultChan := make(chan Result, 1)
	req := &request{done: make(chan struct{}), waiters: []chan Result{resultChan}}
	called := make(chan struct{})
	req.cancel = func() { close(called) }

	finished := make(chan struct{})
	go func() {
		watchCancel(callerCtx, req, resultChan)
		close(finished)
	}()

	close(req.done)

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("expected watchCancel to return once req.done is closed")
	}

	select {
	case <-called:
		t.Fatal("cancel should not be called when the request finished on its own")
	default:
	}
}

func TestWatchCancelCoalescedWaiterDoesNotCancelSibling(t *testing.T) {
	req := &request{done: make(chan struct{})}
	called := make(chan struct{})
	req.cancel = func() { close(called) }

	// two callers coalesced onto the same request
	first := make(chan Result, 1)
	second := make(chan Result, 1)
	req.waiters = []chan Result{first, second}

	secondCtx, secondCancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		watchCancel(secondCtx, req, second)
		close(finished)
	}()

	secondCancel()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("expected watchCancel to return after secondCtx was canceled")
	}

	// second waiter gets resolved with a canceled result...
	select {
	case r := <-second:
		if r.OK {
			t.Fatal("expected canceled result to have OK=false")
		}
	default:
		t.Fatal("expected second waiter to receive a result")
	}

	// ...but the shared pinentry process is NOT killed, since first is
	// still waiting.
	select {
	case <-called:
		t.Fatal("cancel should not fire while a sibling waiter is still pending")
	default:
	}

	// first waiter is untouched and still in the waiters list.
	req.mu.Lock()
	stillWaiting := len(req.waiters) == 1 && req.waiters[0] == first
	req.mu.Unlock()
	if !stillWaiting {
		t.Fatal("expected first waiter to remain registered")
	}
}

func TestWatchCancelLastWaiterCancelsSharedProcess(t *testing.T) {
	req := &request{done: make(chan struct{})}
	called := make(chan struct{})
	req.cancel = func() { close(called) }

	only := make(chan Result, 1)
	req.waiters = []chan Result{only}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		watchCancel(ctx, req, only)
		close(finished)
	}()

	cancel()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("expected watchCancel to return after ctx was canceled")
	}

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("expected shared pinentry process to be canceled once the last waiter cancels")
	}
}
