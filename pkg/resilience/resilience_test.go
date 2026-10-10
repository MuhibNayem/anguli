package resilience

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock so window and cool-down behaviour can
// be tested deterministically instead of with sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Limiter
// ---------------------------------------------------------------------------

func TestNewLimiter_RejectsNonPositiveLimit(t *testing.T) {
	for _, limit := range []int{0, -1, -100} {
		if _, err := NewLimiter(LimiterConfig{Limit: limit}); err == nil {
			t.Errorf("NewLimiter(Limit=%d) = nil error; want rejection", limit)
		}
	}
}

func TestLimiter_NeverExceedsCapacity(t *testing.T) {
	const limit = 8
	l, err := NewLimiter(LimiterConfig{Limit: limit})
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		current int
		peak    int
		wg      sync.WaitGroup
	)
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire(context.Background(), PriorityNormal)
			if err != nil {
				return
			}
			mu.Lock()
			current++
			if current > peak {
				peak = current
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	mu.Lock()
	got := peak
	mu.Unlock()
	if got > limit {
		t.Fatalf("peak concurrency = %d; must never exceed limit %d", got, limit)
	}
	if got < 2 {
		t.Fatalf("peak concurrency = %d; limiter serialised everything, it is not limiting", got)
	}
	if in := l.InFlight(); in != 0 {
		t.Errorf("InFlight() = %d after all work drained; want 0", in)
	}
}

func TestLimiter_ShedsInsteadOfQueueing(t *testing.T) {
	l, err := NewLimiter(LimiterConfig{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	release, err := l.Acquire(context.Background(), PriorityNormal)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	// With no grace period, a second caller must be shed, not queued.
	done := make(chan error, 1)
	go func() {
		_, err := l.Acquire(context.Background(), PriorityNormal)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrShed) {
			t.Fatalf("Acquire error = %v; want ErrShed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire queued instead of shedding; overload becomes unbounded latency")
	}
}

func TestLimiter_GracePeriodThenShed(t *testing.T) {
	clk := newFakeClock()
	l, err := NewLimiter(LimiterConfig{Limit: 1, Grace: 100 * time.Millisecond, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	release, _ := l.Acquire(context.Background(), PriorityNormal)
	defer release()

	start := time.Now()
	_, err = l.Acquire(context.Background(), PriorityNormal)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("Acquire error = %v; want ErrWaitTimeout", err)
	}
	if elapsed < 90*time.Millisecond {
		t.Errorf("shed after %v; should have waited out the 100ms grace period", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("shed after %v; grace period is not bounding the wait", elapsed)
	}
}

func TestLimiter_ReleaseIsIdempotent(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 1})
	release, err := l.Acquire(context.Background(), PriorityNormal)
	if err != nil {
		t.Fatal(err)
	}
	release()
	release() // must not double-return a slot and let the limit exceed 1

	rel2, err := l.Acquire(context.Background(), PriorityNormal)
	if err != nil {
		t.Fatalf("Acquire after a double release failed: %v", err)
	}
	if _, err := l.Acquire(context.Background(), PriorityNormal); !errors.Is(err, ErrShed) {
		t.Fatalf("limit not enforced after double release: err = %v", err)
	}
	rel2()
}

func TestLimiter_ContextCancellationWhileWaiting(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 1, Grace: 10 * time.Second})
	release, _ := l.Acquire(context.Background(), PriorityNormal)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := l.Acquire(ctx, PriorityNormal)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, ErrWaitTimeout) {
			t.Fatalf("Acquire error = %v; want a timeout-class error after cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire ignored context cancellation")
	}
}

func TestLimiter_AlreadyCancelledContextIsRejected(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Acquire(ctx, PriorityNormal); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire with a cancelled context = %v; want context.Canceled", err)
	}
}

func TestLimiter_AllowsWorkAsSlotsFree(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 4})
	for i := 0; i < 4; i++ {
		rel, err := l.Acquire(context.Background(), PriorityCritical)
		if err != nil {
			t.Fatalf("acquire %d failed: %v", i, err)
		}
		rel()
	}
	s := l.Stats()
	if s.Admitted != 4 {
		t.Errorf("Admitted = %d; want 4", s.Admitted)
	}
	if s.Utilisation != 0 {
		t.Errorf("Utilisation = %v after full drain; want 0", s.Utilisation)
	}
}

func TestLimiter_StatsUtilisation(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 4})
	rels := make([]func(), 0, 4)
	for i := 0; i < 2; i++ {
		rel, _ := l.Acquire(context.Background(), PriorityNormal)
		rels = append(rels, rel)
	}
	s := l.Stats()
	if s.InFlight != 2 || s.Utilisation != 0.5 {
		t.Fatalf("Stats = %+v; want InFlight=2 Utilisation=0.5", s)
	}
	for _, r := range rels {
		r()
	}
}

func TestLimiter_DoReleasesOnPanic(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 1})

	func() {
		defer func() { _ = recover() }()
		_ = l.Do(context.Background(), PriorityNormal, func(context.Context) error {
			panic("boom")
		})
	}()

	// A panic inside Do must not leak the slot.
	rel, err := l.Acquire(context.Background(), PriorityNormal)
	if err != nil {
		t.Fatalf("slot leaked after panic: %v", err)
	}
	rel()
}

// TestLimiter_BoundsLatencyUnderOverload is the property this package exists
// for: latency must stay bounded even when far more work arrives than the
// system can serve. Without shedding, queue depth grows with offered load.
func TestLimiter_BoundsLatencyUnderOverload(t *testing.T) {
	const (
		limit      = 4
		offered    = 200
		serviceSet = 20 * time.Millisecond
	)
	l, _ := NewLimiter(LimiterConfig{Limit: limit, Grace: 50 * time.Millisecond})

	var maxLatency atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < offered; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			err := l.Do(ctx, PriorityNormal, func(context.Context) error {
				time.Sleep(serviceSet)
				return nil
			})
			elapsed := time.Since(start).Milliseconds()
			for {
				cur := maxLatency.Load()
				if elapsed <= cur || maxLatency.CompareAndSwap(cur, elapsed) {
					break
				}
			}
			_ = err
		}()
	}
	wg.Wait()

	// 200 offers at 20ms of work against 4 slots is 1s of real work. A bounded
	// limiter must not turn that into unbounded queueing delay.
	if max := time.Duration(maxLatency.Load()) * time.Millisecond; max > 1500*time.Millisecond {
		t.Fatalf("worst-case latency = %v under overload; shedding is not bounding the queue", max)
	}
	if l.Shed() == 0 {
		t.Error("Shed() = 0 under 5x overload; the limiter admitted everything")
	}
}

func TestLimiter_PriorityTracking(t *testing.T) {
	l, _ := NewLimiter(LimiterConfig{Limit: 1, Grace: 500 * time.Millisecond})
	rel, _ := l.Acquire(context.Background(), PriorityCritical)
	defer rel()

	go func() {
		_, _ = l.Acquire(context.Background(), PriorityBackground)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok := l.HighestWaiter(); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("no waiter was tracked while a caller was blocked")
}

func TestPriority_String(t *testing.T) {
	for p, want := range map[Priority]string{
		PriorityBackground: "background",
		PriorityNormal:     "normal",
		PriorityHigh:       "high",
		PriorityCritical:   "critical",
	} {
		if got := p.String(); got != want {
			t.Errorf("Priority(%d).String() = %q; want %q", int(p), got, want)
		}
	}
	if got := Priority(99).String(); !strings.Contains(got, "invalid") {
		t.Errorf("invalid priority String() = %q; want it to flag as invalid", got)
	}
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

func TestNewBreaker_RejectsNonPositiveThreshold(t *testing.T) {
	if _, err := NewBreaker(BreakerConfig{FailureThreshold: 0}); err == nil {
		t.Error("NewBreaker with zero threshold returned nil error")
	}
}

func TestBreaker_OpensOnThreshold(t *testing.T) {
	clk := newFakeClock()
	b, err := NewBreaker(BreakerConfig{
		FailureThreshold: 3,
		FailureWindow:    time.Minute,
		OpenTimeout:      time.Second,
		HalfOpenMaxCalls: 1,
		SuccessThreshold: 1,
		Now:              clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	boom := errors.New("downstream down")
	for i := 0; i < 2; i++ {
		b.Failure(boom)
	}
	if b.State() != StateClosed {
		t.Fatalf("state = %s after 2/%d failures; want closed", b.State(), 3)
	}
	b.Failure(boom)
	if b.State() != StateOpen {
		t.Fatalf("state = %s after 3 failures; want open", b.State())
	}
	if err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("Allow on an open breaker = %v; want ErrBreakerOpen", err)
	}
}

func TestBreaker_FailuresAgeOutOfWindow(t *testing.T) {
	clk := newFakeClock()
	b, _ := NewBreaker(BreakerConfig{
		FailureThreshold: 3, FailureWindow: 10 * time.Second,
		OpenTimeout: time.Second, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Now: clk.Now,
	})
	boom := errors.New("down")

	b.Failure(boom)
	b.Failure(boom)
	clk.Advance(11 * time.Second) // both failures leave the window
	b.Failure(boom)

	if b.State() != StateClosed {
		t.Fatalf("state = %s; failures outside the window must not accumulate into a trip", b.State())
	}
}

func TestBreaker_HalfOpenProbesThenRecovers(t *testing.T) {
	clk := newFakeClock()
	b, _ := NewBreaker(BreakerConfig{
		FailureThreshold: 1, FailureWindow: time.Minute,
		OpenTimeout: 5 * time.Second, HalfOpenMaxCalls: 1, SuccessThreshold: 2,
		Now: clk.Now,
	})
	b.Failure(errors.New("down"))
	if b.State() != StateOpen {
		t.Fatal("breaker did not open")
	}

	if err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Fatal("breaker admitted a call during cool-down")
	}

	clk.Advance(6 * time.Second)
	if err := b.Allow(); err != nil {
		t.Fatalf("half-open probe rejected: %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("state = %s; want half_open after cool-down", b.State())
	}
	// Probe budget is 1, so a second concurrent caller must be shed.
	if err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Error("half-open admitted more probes than HalfOpenMaxCalls")
	}

	b.Success()
	if b.State() != StateHalfOpen {
		t.Errorf("state = %s after 1/%d successes; want half_open", b.State(), 2)
	}
	b.Success()
	if b.State() != StateClosed {
		t.Fatalf("state = %s after recovery; want closed", b.State())
	}
}

func TestBreaker_FailedProbeReopens(t *testing.T) {
	clk := newFakeClock()
	b, _ := NewBreaker(BreakerConfig{
		FailureThreshold: 1, FailureWindow: time.Minute,
		OpenTimeout: 5 * time.Second, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Now: clk.Now,
	})
	b.Failure(errors.New("down"))
	clk.Advance(6 * time.Second)
	if err := b.Allow(); err != nil {
		t.Fatal(err)
	}

	b.Failure(errors.New("still down"))
	if b.State() != StateOpen {
		t.Fatalf("state = %s after a failed probe; want open", b.State())
	}
	if err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Error("breaker reopened but still admitted a call")
	}
}

func TestBreaker_DoRejectsWhenOpen(t *testing.T) {
	clk := newFakeClock()
	b, _ := NewBreaker(BreakerConfig{
		FailureThreshold: 1, FailureWindow: time.Minute,
		OpenTimeout: time.Hour, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Now: clk.Now,
	})
	b.Failure(errors.New("down"))

	var called atomic.Bool
	err := b.Do(context.Background(), func(context.Context) error {
		called.Store(true)
		return nil
	})
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("Do error = %v; want ErrBreakerOpen", err)
	}
	if called.Load() {
		t.Error("Do reached the dependency while the breaker was open")
	}
}

func TestBreaker_ContextErrorDoesNotTripIt(t *testing.T) {
	b, _ := NewBreaker(BreakerConfig{FailureThreshold: 2})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for i := 0; i < 10; i++ {
		_ = b.Do(ctx, func(context.Context) error { return nil })
	}
	if b.State() != StateClosed {
		t.Fatalf("state = %s; a cancelled caller must not be blamed on the dependency", b.State())
	}
}

// TestBreaker_SuccessDoesNotClearRecentFailures pins the sliding-window
// semantics deliberately.
//
// An earlier reading was that a success should reset the failure count. That is
// the wrong design here: a dependency failing 5 requests out of 10 is unhealthy
// even when the last one happened to succeed, and resetting on success lets a
// flapping service flap the breaker open and closed indefinitely - exactly the
// oscillation a breaker exists to suppress. Failages only stop counting once
// they age out of the window.
func TestBreaker_SuccessDoesNotClearRecentFailures(t *testing.T) {
	clk := newFakeClock()
	b, _ := NewBreaker(BreakerConfig{
		FailureThreshold: 3, FailureWindow: time.Minute,
		OpenTimeout: time.Second, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Now: clk.Now,
	})
	boom := errors.New("down")
	b.Failure(boom)
	b.Failure(boom)
	b.Success() // one success must not launder the two recent failures
	b.Failure(boom)

	if b.State() != StateOpen {
		t.Fatalf("state = %s; recent failures inside the window must still accumulate", b.State())
	}
}

func TestBreaker_ConcurrentCallsAreSafe(t *testing.T) {
	b, _ := NewBreaker(BreakerConfig{FailureThreshold: 1000, OpenTimeout: time.Hour})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if j%2 == 0 {
					b.Failure(fmt.Errorf("e%d", i))
				} else {
					b.Success()
				}
				_ = b.Allow()
				_ = b.State()
			}
		}(i)
	}
	wg.Wait()
}

func TestBreaker_Reset(t *testing.T) {
	b, _ := NewBreaker(BreakerConfig{FailureThreshold: 1, OpenTimeout: time.Hour})
	b.Failure(errors.New("down"))
	b.Reset()
	if b.State() != StateClosed {
		t.Fatalf("state = %s after Reset; want closed", b.State())
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("Allow after Reset = %v; want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

func TestDoWithRetry_RetriesTransientThenSucceeds(t *testing.T) {
	var attempts int
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}, func(context.Context) error {
		attempts++
		if attempts < 3 {
			return MarkTransient(errors.New("flaky"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("DoWithRetry = %v; want nil", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d; want 3", attempts)
	}
}

func TestDoWithRetry_DoesNotRetryPermanent(t *testing.T) {
	var attempts int
	permanent := errors.New("permanent")
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts: 5, BaseDelay: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}, func(context.Context) error {
		attempts++
		return permanent
	})
	if !errors.Is(err, permanent) {
		t.Fatalf("DoWithRetry = %v; want the permanent error", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d; a permanent error must not be retried", attempts)
	}
}

func TestDoWithRetry_ExhaustsAttempts(t *testing.T) {
	var attempts int
	err := DoWithRetry(context.Background(), RetryConfig{
		MaxAttempts: 3, BaseDelay: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}, func(context.Context) error {
		attempts++
		return MarkTransient(errors.New("still down"))
	})
	if err == nil {
		t.Fatal("DoWithRetry = nil; want the last error after exhausting attempts")
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d; want exactly MaxAttempts=3", attempts)
	}
}

func TestDoWithRetry_StopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var attempts int
	err := DoWithRetry(ctx, RetryConfig{
		MaxAttempts: 10, BaseDelay: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error {
			cancel()
			return nil
		},
	}, func(context.Context) error {
		attempts++
		return MarkTransient(errors.New("down"))
	})
	if err == nil {
		t.Fatal("DoWithRetry = nil after cancellation")
	}
	if attempts > 2 {
		t.Fatalf("attempts = %d; retries must stop promptly on cancellation", attempts)
	}
}

func TestBackoff_GrowsAndIsCapped(t *testing.T) {
	cfg := RetryConfig{BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second, Jitter: 0}
	var prev time.Duration
	for attempt := 1; attempt <= 6; attempt++ {
		d := backoff(cfg, attempt, func() float64 { return 0 })
		if attempt > 1 && d < prev {
			t.Fatalf("attempt %d delay %v < previous %v; backoff must not shrink", attempt, d, prev)
		}
		if d > cfg.MaxDelay {
			t.Fatalf("attempt %d delay %v exceeds MaxDelay %v", attempt, d, cfg.MaxDelay)
		}
		prev = d
	}
	if prev != time.Second {
		t.Fatalf("final delay = %v; want the MaxDelay cap of 1s", prev)
	}
}

func TestBackoff_JitterStaysWithinBounds(t *testing.T) {
	cfg := RetryConfig{BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.5}
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 0.999999} {
		d := backoff(cfg, 3, func() float64 { return r })
		lo := time.Duration(float64(400*time.Millisecond) * 0.5)
		hi := 400 * time.Millisecond
		if d < lo || d > hi {
			t.Fatalf("jitter(%v) produced %v; want within [%v, %v]", r, d, lo, hi)
		}
	}
	// Jitter must actually vary the delay, otherwise retries synchronise.
	if backoff(cfg, 3, func() float64 { return 0 }) == backoff(cfg, 3, func() float64 { return 1 }) {
		t.Error("jitter produced identical delays; retry storms are still possible")
	}
}

func TestMarkTransientAndIsTransient(t *testing.T) {
	if IsTransient(nil) {
		t.Error("IsTransient(nil) = true")
	}
	if MarkTransient(nil) != nil {
		t.Error("MarkTransient(nil) != nil")
	}
	base := errors.New("x")
	if !IsTransient(MarkTransient(base)) {
		t.Error("IsTransient(MarkTransient(err)) = false")
	}
	if !errors.Is(MarkTransient(base), base) {
		t.Error("MarkTransient broke error unwrapping")
	}
	if IsTransient(base) {
		t.Error("a bare error must not be treated as transient")
	}
}

func TestBreaker_DoWithRetryStillSheds(t *testing.T) {
	clk := newFakeClock()
	b, _ := NewBreaker(BreakerConfig{
		FailureThreshold: 1, FailureWindow: time.Minute,
		OpenTimeout: time.Hour, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		Now: clk.Now,
	})
	var calls int
	cfg := RetryConfig{
		MaxAttempts: 3, BaseDelay: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	// First call fails and opens the breaker.
	_ = b.DoWithRetry(context.Background(), cfg, func(context.Context) error {
		calls++
		return MarkTransient(errors.New("down"))
	})
	firstCalls := calls

	err := b.DoWithRetry(context.Background(), cfg, func(context.Context) error {
		calls++
		return nil
	})
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("DoWithRetry = %v; want ErrBreakerOpen once tripped", err)
	}
	if calls != firstCalls {
		t.Errorf("dependency was called %d more times while open; retry storm not prevented",
			calls-firstCalls)
	}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

func TestMetrics_HandlerExposesSeries(t *testing.T) {
	m := NewMetrics()
	l, _ := NewLimiter(LimiterConfig{Limit: 2})
	b, _ := NewBreaker(BreakerConfig{FailureThreshold: 1, OpenTimeout: time.Hour})
	b.Failure(errors.New("down"))

	m.ObserveLimiter("verify", l.Stats())
	m.ObserveShed("verify", PriorityLow(), "timeout")
	m.ObserveBreaker("biometric", b)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"anguli_limiter_in_flight",
		"anguli_limiter_utilisation_ratio",
		"anguli_limiter_shed_total",
		"anguli_circuit_breaker_state",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing %q", want)
		}
	}
	if !strings.Contains(body, `anguli_circuit_breaker_state{breaker="biometric",state="open"} 1`) {
		t.Error("/metrics did not report the breaker as open")
	}
}

func TestMetrics_BreakerObservationIsNotCumulative(t *testing.T) {
	m := NewMetrics()
	b, _ := NewBreaker(BreakerConfig{FailureThreshold: 10, OpenTimeout: time.Hour})

	m.ObserveBreaker("x", b)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	first := rec.Body.String()

	// Observing again must report the same absolute totals, not add to them.
	m.ObserveBreaker("x", b)
	rec2 := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	extract := func(s string) string {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "anguli_circuit_breaker_failure_total") {
				return line
			}
		}
		return ""
	}
	if extract(first) != extract(rec2.Body.String()) {
		t.Fatalf("breaker series drifted between observations:\n%q\nvs\n%q",
			extract(first), extract(rec2.Body.String()))
	}
}

func TestParseIntDefault(t *testing.T) {
	for in, want := range map[string]int{"": 7, "42": 42, "abc": 7, "-3": -3} {
		if got := ParseIntDefault(in, 7); got != want {
			t.Errorf("ParseIntDefault(%q, 7) = %d; want %d", in, got, want)
		}
	}
}

// PriorityLow is a readability alias used by the metrics test.
func PriorityLow() Priority { return PriorityBackground }
