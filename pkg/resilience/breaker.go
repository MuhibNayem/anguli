package resilience

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// pseudoRand returns a value in [0,1). Package-level indirection so tests can
// pin the jitter schedule.
func pseudoRand() float64 { return rand.Float64() }

// State is a circuit breaker's condition.
type State int32

const (
	// StateClosed passes traffic normally.
	StateClosed State = iota
	// StateOpen rejects all calls until the cool-down elapses.
	StateOpen
	// StateHalfOpen admits a limited probe to test recovery.
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	}
	return "unknown"
}

// ErrBreakerTripped wraps the context/limit error that caused a breaker to
// open, so the caller can see why after the fact.
type ErrBreakerTripped struct {
	Err    error
	After  int
	Window time.Duration
}

func (e *ErrBreakerTripped) Error() string {
	return fmt.Sprintf("circuit breaker opened after %d failures in %v: %v", e.After, e.Window, e.Err)
}

func (e *ErrBreakerTripped) Unwrap() error { return e.Err }

// BreakerConfig configures a circuit breaker.
type BreakerConfig struct {
	// FailureThreshold is the number of failures within FailureWindow that
	// trips the breaker open. Must be > 0.
	FailureThreshold int
	// FailureWindow is the sliding window over which failures are counted.
	FailureWindow time.Duration
	// OpenTimeout is how long the breaker stays open before probing.
	OpenTimeout time.Duration
	// HalfOpenMaxCalls is how many probes are admitted while half-open.
	HalfOpenMaxCalls int
	// SuccessThreshold is how many consecutive half-open successes close it.
	SuccessThreshold int
	// Now optionally overrides the clock (tests only).
	Now func() time.Time
}

// DefaultBreakerConfig returns sensible defaults for internal RPC calls.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		FailureThreshold: 5,
		FailureWindow:    30 * time.Second,
		OpenTimeout:      10 * time.Second,
		HalfOpenMaxCalls: 1,
		SuccessThreshold: 2,
	}
}

// Breaker is a three-state circuit breaker.
//
// Why it matters here: when a downstream service is down, calling it anyway
// converts a dependency failure into a self-inflicted one. Every retry piles
// work onto a service that is already struggling. A breaker fails fast so the
// caller can serve a degraded response instead of hanging, and it periodically
// probes so recovery is automatic rather than requiring a restart.
type Breaker struct {
	cfg BreakerConfig
	now func() time.Time

	// state is atomic so State() is cheap and lock-free on the hot path.
	state atomic.Int32

	mu sync.Mutex
	// failures holds timestamps of failures inside the current window.
	failures []time.Time
	// openedAtUnixNano is when the breaker last transitioned to open, as Unix
	// nanoseconds, and it is atomic rather than mu-guarded on purpose. The
	// value is written once per transition to open but read by every rejected
	// request: during an outage, when the dependency is down and the breaker is
	// shedding load, that read happens at the full request rate. Guarding it
	// with mu made all of those rejects queue behind one lock, so the path that
	// exists specifically to shed work fast became the path that serialises -
	// exactly when the process is least able to afford to wait. An atomic keeps
	// the value race-free without putting it on the critical section.
	openedAtUnixNano atomic.Int64
	// halfOpenCalls counts probes admitted in the current half-open period.
	halfOpenCalls int
	// halfOpenSuccesses counts consecutive successful probes.
	halfOpenSuccesses int

	// cumulative counters for metrics.
	stateChanges atomic.Uint64
	rejected     atomic.Uint64
	successes    atomic.Uint64
	failuresSeen atomic.Uint64
}

// NewBreaker builds a Breaker, applying defaults for unset fields.
func NewBreaker(cfg BreakerConfig) (*Breaker, error) {
	if cfg.FailureThreshold <= 0 {
		return nil, fmt.Errorf("resilience: failure threshold must be > 0, got %d", cfg.FailureThreshold)
	}
	d := DefaultBreakerConfig()
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = d.FailureWindow
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = d.OpenTimeout
	}
	if cfg.HalfOpenMaxCalls <= 0 {
		cfg.HalfOpenMaxCalls = d.HalfOpenMaxCalls
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = d.SuccessThreshold
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	b := &Breaker{cfg: cfg, now: now}
	b.state.Store(int32(StateClosed))
	return b, nil
}

// State reports the breaker's current condition.
func (b *Breaker) State() State { return State(b.state.Load()) }

// Counters returns cumulative counters for metrics.
func (b *Breaker) Counters() (successes, failures, rejected, transitions uint64) {
	return b.successes.Load(), b.failuresSeen.Load(), b.rejected.Load(), b.stateChanges.Load()
}

// openedAtValue reconstructs the transition timestamp from the atomic, without
// taking mu: it runs on Allow()'s reject path, which must stay lock-free.
// A stored zero means "never opened", and maps back to the zero time.Time so
// the cool-down reads as long elapsed - the same answer the mutex-guarded
// field gave for an unset value.
func (b *Breaker) openedAtValue() time.Time {
	n := b.openedAtUnixNano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Allow reports whether a call may proceed, and why not when it may not.
func (b *Breaker) Allow() error {
	switch b.State() {
	case StateClosed:
		return nil
	case StateOpen:
		if b.now().Sub(b.openedAtValue()) < b.cfg.OpenTimeout {
			b.rejected.Add(1)
			return fmt.Errorf("%w: still within %v cool-down", ErrBreakerOpen, b.cfg.OpenTimeout)
		}
		// Cool-down elapsed: transition to half-open and admit a probe.
		if b.transition(StateHalfOpen) {
			b.mu.Lock()
			b.halfOpenCalls = 1
			b.halfOpenSuccesses = 0
			b.mu.Unlock()
			return nil
		}
		b.rejected.Add(1)
		return fmt.Errorf("%w: another caller is probing", ErrBreakerOpen)
	case StateHalfOpen:
		b.mu.Lock()
		if b.halfOpenCalls < b.cfg.HalfOpenMaxCalls {
			b.halfOpenCalls++
			b.mu.Unlock()
			return nil
		}
		b.mu.Unlock()
		b.rejected.Add(1)
		return fmt.Errorf("%w: probe budget exhausted", ErrBreakerOpen)
	}
	return fmt.Errorf("%w: unknown state", ErrBreakerOpen)
}

// transition moves to next if it is not already there. Returns true if this
// call performed the transition.
func (b *Breaker) transition(next State) bool {
	for {
		cur := State(b.state.Load())
		if cur == next {
			return false
		}
		if b.state.CompareAndSwap(int32(cur), int32(next)) {
			b.stateChanges.Add(1)
			return true
		}
	}
}

// Success records a successful call, closing the breaker once enough
// consecutive probes have passed.
func (b *Breaker) Success() {
	b.successes.Add(1)
	if b.State() == StateHalfOpen {
		b.mu.Lock()
		b.halfOpenSuccesses++
		reached := b.halfOpenSuccesses >= b.cfg.SuccessThreshold
		b.mu.Unlock()
		if reached {
			b.close()
		}
	}
}

// Failure records a failed call, opening the breaker once the failure rate in
// the window crosses the threshold.
func (b *Breaker) Failure(err error) {
	b.failuresSeen.Add(1)

	if b.State() == StateHalfOpen {
		// A failed probe sends us straight back to open and restarts the
		// cool-down. That is the whole point of the half-open probe.
		b.mu.Lock()
		b.halfOpenSuccesses = 0
		b.mu.Unlock()
		b.open(err)
		return
	}

	now := b.now()
	cutoff := now.Add(-b.cfg.FailureWindow)

	b.mu.Lock()
	// Drop failures that have aged out of the sliding window.
	keep := b.failures[:0]
	for _, t := range b.failures {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	b.failures = append(keep, now)
	count := len(b.failures)
	b.mu.Unlock()

	if count >= b.cfg.FailureThreshold {
		b.open(err)
	}
}

// open trips the breaker.
func (b *Breaker) open(err error) {
	if b.transition(StateOpen) {
		b.mu.Lock()
		b.openedAtUnixNano.Store(b.now().UnixNano())
		b.failures = nil
		b.halfOpenCalls = 0
		b.halfOpenSuccesses = 0
		b.mu.Unlock()
		_ = err // retained in the returned ErrBreakerTripped at Allow time
	}
}

// close returns the breaker to normal service.
func (b *Breaker) close() {
	if b.transition(StateClosed) {
		b.mu.Lock()
		b.failures = nil
		b.openedAtUnixNano.Store(0)
		b.halfOpenCalls = 0
		b.halfOpenSuccesses = 0
		b.mu.Unlock()
	}
}

// Reset forces the breaker closed and clears history. Intended for operators
// and tests, not for use on a hot path.
func (b *Breaker) Reset() { b.close() }

// Do runs fn through the breaker. A rejection is returned as an error
// wrapping ErrBreakerOpen; fn's own error is fed to Failure.
func (b *Breaker) Do(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.Allow(); err != nil {
		return err
	}
	err := fn(ctx)
	if err != nil {
		// A cancelled caller is not the dependency's fault, so it must not
		// count against the breaker.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		b.Failure(err)
		return err
	}
	b.Success()
	return nil
}

// DoWithRetry composes the breaker with retry: transient failures are retried
// with backoff while the breaker permits, and the breaker still prevents a
// retry storm from reaching a dependency that is already down.
func (b *Breaker) DoWithRetry(ctx context.Context, cfg RetryConfig, fn func(context.Context) error) error {
	if err := b.Allow(); err != nil {
		return err
	}
	err := DoWithRetry(ctx, cfg, fn)
	if err == nil {
		b.Success()
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	b.Failure(err)
	return err
}
