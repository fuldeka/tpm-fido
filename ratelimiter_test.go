package main

import (
	"testing"
	"time"
)

func TestRateLimiterEnforcesMinimumInterval(t *testing.T) {
	rl := newRateLimiter(50 * time.Millisecond)

	start := time.Now()
	rl.Wait()
	rl.Wait()
	rl.Wait()
	elapsed := time.Since(start)

	if elapsed < 100*time.Millisecond {
		t.Fatalf("expected at least 2 intervals (100ms) between 3 calls, got %s", elapsed)
	}
}

func TestRateLimiterDoesNotDelayWellSpacedCalls(t *testing.T) {
	rl := newRateLimiter(20 * time.Millisecond)

	rl.Wait()
	time.Sleep(30 * time.Millisecond)

	start := time.Now()
	rl.Wait()
	elapsed := time.Since(start)

	if elapsed > 10*time.Millisecond {
		t.Fatalf("expected near-zero wait for a call spaced beyond the interval, got %s", elapsed)
	}
}
