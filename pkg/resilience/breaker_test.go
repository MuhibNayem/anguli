package resilience

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// openBreaker builds a breaker that is already open and stays open for the
// whole test: the fake clock never advances past OpenTimeout, so every Allow()
// takes the StateOpen reject path.
func openBreaker(t *testing.T) (*Breaker, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	b, err := NewBreaker(BreakerConfig{
		FailureThreshold: 1, FailureWindow: time.Minute,
		OpenTimeout: time.Hour, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Now: clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	b.Failure(errors.New("down"))
	if b.State() != StateOpen {
		t.Fatal("breaker did not open")
	}
	return b, clk
}

// TestBreaker_OpenRejectPathDoesNotTakeMutex pins the reason the transition
// timestamp is atomic. During an outage the reject path runs at the full
// request rate, so guarding that single read with mu turns the one path whose
// job is to shed work fast into the one path that queues - and it queues behind
// the Failure() calls pruning the sliding window too. Here the test itself
// holds mu, standing in for that concurrent holder, so a mutex-guarded
// timestamp shows up as a blocked reject rather than as a slowdown too subtle
// to assert on.
func TestBreaker_OpenRejectPathDoesNotTakeMutex(t *testing.T) {
	b, _ := openBreaker(t)

	b.mu.Lock()
	defer b.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- b.Allow() }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrBreakerOpen) {
			t.Fatalf("Allow on an open breaker = %v; want ErrBreakerOpen", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Allow() blocked on mu during cool-down; the open-transition timestamp must be read without the lock")
	}
}

// TestBreaker_ConcurrentAllowWhileOpenIsRaceFree covers the reject path under
// the race detector: many callers rejecting at once against an open breaker.
// All of them must be shed, and none may observe a corrupt timestamp.
func TestBreaker_ConcurrentAllowWhileOpenIsRaceFree(t *testing.T) {
	b, _ := openBreaker(t)

	const callers = 64
	const rounds = 200

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				if err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
					t.Errorf("Allow on an open breaker = %v; want ErrBreakerOpen", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if b.State() != StateOpen {
		t.Fatalf("state = %s after concurrent rejects; want open", b.State())
	}
	_, _, rejected, _ := b.Counters()
	if rejected != callers*rounds {
		t.Errorf("rejected = %d; want %d", rejected, callers*rounds)
	}
}

// TestBreaker_ReopenRacesAllowReads covers the transition timestamp being
// written while others are reading it: the timestamp is stored on every
// Closed->Open transition, so a breaker that keeps re-tripping under a swarm of
// callers would expose an unsynchronised field here. Because the state is
// genuinely churning, each Allow() may legitimately see closed (nil) or open
// (ErrBreakerOpen); anything else, or a data race, is the defect.
func TestBreaker_ReopenRacesAllowReads(t *testing.T) {
	b, _ := openBreaker(t)

	const callers = 16
	const rounds = 300

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for r := 0; r < rounds; r++ {
				if err := b.Allow(); err != nil && !errors.Is(err, ErrBreakerOpen) {
					t.Errorf("Allow = %v; want nil or ErrBreakerOpen", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for r := 0; r < rounds; r++ {
			b.Reset()
			b.Failure(errors.New("down"))
		}
	}()
	close(start)
	wg.Wait()

	if b.State() != StateOpen {
		t.Fatalf("state = %s after re-tripping; want open", b.State())
	}
}

// TestBreaker_NeverHalfOpensWithoutAnElapsedCoolDown is a regression test for a
// race in the breaker that made it leak a request during an outage.
//
// The breaker published its open state before its cool-down timestamp. A
// concurrent Allow() that landed in that window read the timestamp as unset,
// computed the cool-down as b.now().Sub(zeroTime) - which is years - concluded
// it had elapsed, and moved the breaker to half-open. That admitted a probe
// that the cool-down existed to reject, and parked the breaker in half-open
// with its single probe slot already spent.
//
// It showed up as TestBreaker_ReopenRacesAllowReads failing about 2% of runs,
// which is worse than a visible bug: an intermittently red suite cannot
// distinguish a regression from noise.
//
// This test is deliberately more direct than that one. The clock is fake and
// never advanced, so half-open is unreachable by design, and any observation of
// it is a direct signal that a caller raced the state publication rather than
// inference from a final assertion.
func TestBreaker_NeverHalfOpensWithoutAnElapsedCoolDown(t *testing.T) {
	b, _ := openBreaker(t) // OpenTimeout is an hour and the clock never moves

	var halfOpen atomic.Bool
	var stop atomic.Bool
	var wg sync.WaitGroup

	// Trips the breaker continuously. Each Failure trips it (threshold 1) and
	// Reset returns it to closed so the next one trips again.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			b.Reset()
			b.Failure(errors.New("down"))
		}
	}()

	// Readers spin on Allow. Any of them landing in the publication window
	// observes half-open.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if err := b.Allow(); err != nil && !errors.Is(err, ErrBreakerOpen) {
					t.Errorf("Allow = %v; want nil or ErrBreakerOpen", err)
					return
				}
			}
		}()
	}

	// Let the churn run, then stop and check.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if b.State() == StateHalfOpen {
			halfOpen.Store(true)
			break
		}
	}
	stop.Store(true)
	wg.Wait()

	if halfOpen.Load() || b.State() == StateHalfOpen {
		t.Fatalf("breaker reached half-open with the cool-down never elapsing; " +
			"a caller raced the cool-down timestamp publication")
	}
}
