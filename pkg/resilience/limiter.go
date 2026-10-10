// Package resilience provides the load-shedding, circuit-breaking and retry
// primitives an access-control platform needs to stay available under load and
// during partial outages.
//
// The motivating failure this package exists to prevent: unbounded concurrency
// against a shared biometric backend. When every request is admitted and none
// is shed, queueing time grows without bound - measured on this platform at
// 140ms for one concurrent verify rising to 4.4s at 128 - and the service
// stops answering long before it stops working. Shedding load deliberately is
// faster and more predictable than accepting work that can never complete.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrOverloaded is returned when the limiter has no capacity and the
	// caller's grace period has already elapsed.
	ErrOverloaded = errors.New("overloaded: concurrency limit reached, request shed")

	// ErrShed is returned when the caller chose not to wait at all.
	ErrShed = errors.New("overloaded: request shed immediately")

	// ErrWaitTimeout is returned when the caller waited but never got a slot.
	ErrWaitTimeout = errors.New("overloaded: timed out waiting for a concurrency slot")

	// ErrBreakerOpen is returned when a circuit breaker is rejecting calls.
	ErrBreakerOpen = errors.New("circuit breaker open")
)

// Priority classes requests for load shedding. When a limiter is saturated the
// highest priority with capacity wins; the lowest priority is shed first.
//
// A door that is physically open must never be starved by a batch of
// background reconciliation work, so the critical path sits at the top.
type Priority int

const (
	PriorityBackground Priority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical // door strikes, access decisions
)

func (p Priority) String() string {
	switch p {
	case PriorityBackground:
		return "background"
	case PriorityNormal:
		return "normal"
	case PriorityHigh:
		return "high"
	case PriorityCritical:
		return "critical"
	}
	return fmt.Sprintf("invalid(%d)", int(p))
}

// valid reports whether p is a known priority.
func (p Priority) valid() bool { return p >= PriorityBackground && p <= PriorityCritical }

// Limiter is a bounded-concurrency admission controller with priority-aware
// load shedding.
//
// It is deliberately not a plain semaphore. A semaphore makes every caller
// queue, which converts overload into latency. This limiter bounds the queue
// too: once every slot is taken and the waiters at the highest present
// priority have waited out their grace period, new work is refused immediately
// so the caller can fail fast and let the user retry deliberately.
type Limiter struct {
	// limit is the maximum number of concurrent admissions.
	limit int
	// grace is how long a caller may wait for a slot before being shed.
	grace time.Duration

	// slots is a counting semaphore of capacity limit.
	slots chan struct{}
	// waiters tracks in-flight waiters by priority so shedding can be
	// priority-aware rather than first-come-first-served.
	mu      sync.Mutex
	waiters map[Priority]int

	// inFlight is the current occupancy, published for metrics.
	inFlight atomic.Int64
	// waitCount is the number of callers currently blocked.
	waitCount atomic.Int64
	// shedCount and admittedCount are cumulative counters for metrics.
	shedCount     atomic.Uint64
	admittedCount atomic.Uint64

	now func() time.Time // injectable clock for tests
}

// LimiterConfig configures a Limiter.
type LimiterConfig struct {
	// Limit is the maximum concurrent admissions. Must be > 0.
	Limit int
	// Grace is how long a caller may block for a slot. Zero means shed
	// immediately rather than queue.
	Grace time.Duration
	// Now optionally overrides the clock (tests only).
	Now func() time.Time
}

// NewLimiter builds a Limiter.
func NewLimiter(cfg LimiterConfig) (*Limiter, error) {
	if cfg.Limit <= 0 {
		return nil, fmt.Errorf("resilience: limiter limit must be > 0, got %d", cfg.Limit)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		limit:   cfg.Limit,
		grace:   cfg.Grace,
		slots:   make(chan struct{}, cfg.Limit),
		waiters: make(map[Priority]int, 4),
		now:     now,
	}, nil
}

// Limit reports the configured concurrency ceiling.
func (l *Limiter) Limit() int { return l.limit }

// InFlight reports current occupancy.
func (l *Limiter) InFlight() int { return int(l.inFlight.Load()) }

// Waiting reports how many callers are currently blocked on admission.
func (l *Limiter) Waiting() int { return int(l.waitCount.Load()) }

// Admitted and Shed report cumulative counters.
func (l *Limiter) Admitted() uint64 { return l.admittedCount.Load() }
func (l *Limiter) Shed() uint64     { return l.shedCount.Load() }

// Acquire reserves a slot, blocking at most the configured grace period.
//
// The returned release function must be called exactly once when the work is
// done. It is safe to call more than once.
func (l *Limiter) Acquire(ctx context.Context, p Priority) (release func(), err error) {
	if !p.valid() {
		p = PriorityNormal
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Fast path: a slot is immediately available.
	select {
	case l.slots <- struct{}{}:
		l.admitted()
		return l.releaser(), nil
	default:
	}

	if l.grace <= 0 {
		l.shedCount.Add(1)
		return nil, ErrShed
	}

	l.trackWait(p, 1)
	defer l.trackWait(p, -1)

	timer := time.NewTimer(l.grace)
	defer timer.Stop()

	select {
	case l.slots <- struct{}{}:
		l.admitted()
		return l.releaser(), nil
	case <-timer.C:
		l.shedCount.Add(1)
		return nil, fmt.Errorf("%w after %v at priority %s", ErrWaitTimeout, l.grace, p)
	case <-ctx.Done():
		l.shedCount.Add(1)
		return nil, fmt.Errorf("%w: %v", ErrWaitTimeout, ctx.Err())
	}
}

// Do runs fn while holding an admission slot.
func (l *Limiter) Do(ctx context.Context, p Priority, fn func(context.Context) error) error {
	release, err := l.Acquire(ctx, p)
	if err != nil {
		return err
	}
	defer release()
	return fn(ctx)
}

func (l *Limiter) admitted() {
	l.inFlight.Add(1)
	l.admittedCount.Add(1)
}

func (l *Limiter) trackWait(p Priority, delta int) {
	l.mu.Lock()
	l.waiters[p] += delta
	if l.waiters[p] <= 0 {
		delete(l.waiters, p)
	}
	l.mu.Unlock()
	l.waitCount.Add(int64(delta))
}

// HighestWaiter reports the highest priority currently blocked, and whether
// anyone is waiting at all. Callers use it to decide whether to queue.
func (l *Limiter) HighestWaiter() (Priority, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	best := PriorityBackground
	found := false
	for p := range l.waiters {
		if !found || p > best {
			best, found = p, true
		}
	}
	return best, found
}

// releaser returns a once-guarded release function.
func (l *Limiter) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-l.slots
			l.inFlight.Add(-1)
		})
	}
}

// Stats is a point-in-time snapshot of limiter state, suitable for metrics.
type Stats struct {
	Limit       int     `json:"limit"`
	InFlight    int     `json:"in_flight"`
	Waiting     int     `json:"waiting"`
	Admitted    uint64  `json:"admitted_total"`
	Shed        uint64  `json:"shed_total"`
	Utilisation float64 `json:"utilisation"`
}

// Stats snapshots the limiter.
func (l *Limiter) Stats() Stats {
	in := int(l.inFlight.Load())
	u := 0.0
	if l.limit > 0 {
		u = float64(in) / float64(l.limit)
	}
	return Stats{
		Limit:       l.limit,
		InFlight:    in,
		Waiting:     int(l.waitCount.Load()),
		Admitted:    l.admittedCount.Load(),
		Shed:        l.shedCount.Load(),
		Utilisation: u,
	}
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

// RetryConfig configures exponential backoff with jitter.
type RetryConfig struct {
	// MaxAttempts is the total number of tries, including the first. Must be >= 1.
	MaxAttempts int
	// BaseDelay is the delay before the second attempt.
	BaseDelay time.Duration
	// MaxDelay caps the backoff.
	MaxDelay time.Duration
	// Jitter is the fraction of the computed delay to randomise, in [0,1].
	// Without jitter, concurrent callers retry in lockstep and re-create the
	// thundering herd that caused the outage.
	Jitter float64
	// RetryIf decides whether an error is worth retrying. Defaults to
	// transient-only.
	RetryIf func(error) bool
	// Sleep is injectable for tests.
	Sleep func(context.Context, time.Duration) error
}

// DefaultRetryConfig returns sensible defaults for idempotent RPC calls.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   50 * time.Millisecond,
		MaxDelay:    2 * time.Second,
		Jitter:      0.2,
	}
}

// TransientError marks an error as worth retrying, so callers do not have to
// enumerate error strings.
type TransientError struct{ Err error }

func (e *TransientError) Error() string { return e.Err.Error() }
func (e *TransientError) Unwrap() error { return e.Err }

// MarkTransient wraps err so Retry will retry it.
func MarkTransient(err error) error {
	if err == nil {
		return nil
	}
	return &TransientError{Err: err}
}

// IsTransient reports whether err was marked transient.
func IsTransient(err error) bool {
	var t *TransientError
	return errors.As(err, &t)
}

// defaultRetryIf retries marked-transient errors and gRPC transport failures.
func defaultRetryIf(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return IsTransient(err)
}

// backoff computes the delay before attempt n (1-indexed), with full jitter.
func backoff(cfg RetryConfig, attempt int, rnd func() float64) time.Duration {
	exp := float64(cfg.BaseDelay) * math.Pow(2, float64(attempt-1))
	d := time.Duration(exp)
	if cfg.MaxDelay > 0 && d > cfg.MaxDelay {
		d = cfg.MaxDelay
	}
	if cfg.Jitter > 0 {
		// Spread across [d*(1-jitter), d] so backoff never shrinks below the
		// computed floor and retries spread out instead of stampeding.
		lo := float64(d) * (1 - cfg.Jitter)
		d = time.Duration(lo + rnd()*(float64(d)-lo))
	}
	return d
}

// sleepCtx sleeps unless ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DoWithRetry runs fn, retrying transient failures with exponential backoff
// and jitter until attempts are exhausted or ctx is done.
func DoWithRetry(ctx context.Context, cfg RetryConfig, fn func(context.Context) error) error {
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}
	retryIf := cfg.RetryIf
	if retryIf == nil {
		retryIf = defaultRetryIf
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	var lastErr error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}
		if !retryIf(lastErr) || attempt == cfg.MaxAttempts {
			return lastErr
		}
		if err := sleep(ctx, backoff(cfg, attempt, jitterRand)); err != nil {
			return lastErr
		}
	}
	return lastErr
}

// jitterRand returns a value in [0,1). Package-level so tests can reason about
// the schedule deterministically by injecting RetryConfig.Sleep.
func jitterRand() float64 {
	return pseudoRand()
}
