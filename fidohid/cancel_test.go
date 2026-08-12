package fidohid

import (
	"context"
	"testing"
)

func newTestToken() *SoftToken {
	return &SoftToken{cancelFns: make(map[uint32]context.CancelFunc)}
}

func TestCancelRequestAbortsRegisteredContext(t *testing.T) {
	tok := newTestToken()

	ctx := tok.registerRequest(1)
	if ctx.Err() != nil {
		t.Fatal("freshly registered context should not be done")
	}

	tok.cancelRequest(1)

	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected context to be canceled after cancelRequest")
	}
}

func TestCancelRequestUnknownChannelIsNoop(t *testing.T) {
	tok := newTestToken()
	// Should not panic even though no request was ever registered for
	// this channel -- a stray CANCEL for an unknown/finished channel is
	// legal per CTAPHID and must be a harmless no-op.
	tok.cancelRequest(99)
}

func TestClearRequestPreventsLaterCancel(t *testing.T) {
	tok := newTestToken()

	ctx := tok.registerRequest(1)
	tok.clearRequest(1)

	// A CANCEL arriving after the handler already finished (and cleared
	// its slot) must not retroactively cancel that already-completed
	// request's context.
	tok.cancelRequest(1)

	select {
	case <-ctx.Done():
		t.Fatal("context should not be canceled: request was cleared before cancelRequest")
	default:
	}
}

func TestRegisterRequestReplacesPreviousOnSameChannel(t *testing.T) {
	tok := newTestToken()

	first := tok.registerRequest(1)
	second := tok.registerRequest(1)

	select {
	case <-first.Done():
	default:
		t.Fatal("registering a new request on the same channel should cancel the previous one")
	}

	if second.Err() != nil {
		t.Fatal("the new request's context should still be live")
	}
}

func TestRegisterRequestIndependentChannels(t *testing.T) {
	tok := newTestToken()

	ctx1 := tok.registerRequest(1)
	ctx2 := tok.registerRequest(2)

	tok.cancelRequest(1)

	select {
	case <-ctx1.Done():
	default:
		t.Fatal("expected channel 1's context to be canceled")
	}

	if ctx2.Err() != nil {
		t.Fatal("canceling channel 1 should not affect channel 2")
	}
}
