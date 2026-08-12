package pinentry

import (
	"context"
	"testing"
	"time"
)

func TestWatchCancelCallsCancelOnCallerCtxDone(t *testing.T) {
	callerCtx, callerCancel := context.WithCancel(context.Background())

	req := &request{done: make(chan struct{})}
	called := make(chan struct{})
	req.cancel = func() { close(called) }

	go watchCancel(callerCtx, req)

	callerCancel()

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("expected req.cancel to be called after callerCtx was canceled")
	}
}

func TestWatchCancelStopsOnRequestDoneWithoutCanceling(t *testing.T) {
	callerCtx := context.Background() // never canceled

	req := &request{done: make(chan struct{})}
	called := make(chan struct{})
	req.cancel = func() { close(called) }

	finished := make(chan struct{})
	go func() {
		watchCancel(callerCtx, req)
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
