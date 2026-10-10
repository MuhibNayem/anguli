package ratelimit_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"finger-scanner/pkg/security/ratelimit"
)

// clock is a manually advanced time source, so refill and eviction are tested
// exactly rather than approximated with sleeps.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Unix(1_700_000_000, 0)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestKeyedLimiterIsolatesCallers(t *testing.T) {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: 10, Burst: 2})
	if err != nil {
		t.Fatal(err)
	}

	// One caller exhausts its bucket.
	for i := 0; i < 2; i++ {
		if !l.Allow("noisy-door") {
			t.Fatalf("noisy-door request %d should have been allowed", i)
		}
	}
	if l.Allow("noisy-door") {
		t.Fatal("noisy-door should be throttled after its burst")
	}

	// A different caller must be entirely unaffected. This is the property a
	// single global bucket cannot provide: every turnstile on a site shares one
	// API key today, so a global limit is either useless or site-wide.
	for i := 0; i < 2; i++ {
		if !l.Allow("quiet-door") {
			t.Fatalf("quiet-door request %d should have been allowed", i)
		}
	}
}

func TestKeyedLimiterRefillsAtConfiguredRate(t *testing.T) {
	c := newClock()
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{
		Rate: 4, Burst: 1, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !l.Allow("door") {
		t.Fatal("first request should be allowed")
	}
	if l.Allow("door") {
		t.Fatal("burst of 1 should be exhausted")
	}

	// 4 tokens/second: a quarter second buys exactly one token.
	c.advance(250 * time.Millisecond)
	if !l.Allow("door") {
		t.Fatal("a quarter second at 4/s should refill exactly one token")
	}
	if l.Allow("door") {
		t.Fatal("only one token should have been refilled")
	}

	// Refill is capped at the burst, so idling does not bank unlimited credit.
	c.advance(time.Hour)
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("door") {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("after a long idle period a burst of 1 should allow exactly 1, got %d", allowed)
	}
}

func TestKeyedLimiterRejectsNonPositiveRate(t *testing.T) {
	// A zero or negative rate is a configuration error, not something to clamp.
	// On a door endpoint it does not degrade gracefully: it stops employees
	// getting through, so it has to stop the process at startup instead.
	for _, rate := range []float64{0, -1} {
		if _, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: rate}); err == nil {
			t.Fatalf("rate=%v should have been rejected", rate)
		}
	}
}

func TestKeyedLimiterBoundsTableAndThrottlesOverflow(t *testing.T) {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{
		Rate: 1, Burst: 1, MaxKeys: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	l.Allow("a")
	l.Allow("b")

	// A third distinct key cannot get its own bucket and must draw from the
	// shared overflow bucket, so an attacker minting unique keys is throttled
	// rather than served.
	if l.Tracked() != 2 {
		t.Fatalf("tracked=%d, want 2", l.Tracked())
	}
	allowed := 0
	for i := 0; i < 5; i++ {
		if l.Allow("attacker-" + string(rune('a'+i))) {
			allowed++
		}
	}
	if l.Overflowed() == 0 {
		t.Fatal("expected overflow to be observed once the table is full")
	}
	// The overflow bucket itself must enforce the same rate, or the cap would
	// be the only thing standing between an attacker and unlimited service.
	if allowed == 5 {
		t.Fatal("overflow bucket did not throttle; the key cap alone bounded nothing")
	}
}

func TestKeyedLimiterSweepEvictsIdleCallers(t *testing.T) {
	c := newClock()
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{
		Rate: 10, Burst: 5, MaxKeys: 4, IdleTTL: time.Minute, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{"a", "b", "c", "d"} {
		l.Allow(k)
	}
	if l.Tracked() != 4 {
		t.Fatalf("tracked=%d, want 4", l.Tracked())
	}

	c.advance(90 * time.Second)
	if removed := l.Sweep(); removed != 4 {
		t.Fatalf("sweep removed %d, want 4", removed)
	}
	if l.Tracked() != 0 {
		t.Fatalf("tracked=%d after sweep, want 0", l.Tracked())
	}

	// An evicted caller that comes back gets a fresh, full bucket rather than
	// being permanently penalised for having been idle.
	if !l.Allow("a") {
		t.Fatal("an evicted caller should be admitted again")
	}
}

func TestKeyedLimiterActiveCallerSurvivesSweep(t *testing.T) {
	c := newClock()
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{
		Rate: 10, Burst: 10, IdleTTL: time.Minute, Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	l.Allow("busy")
	c.advance(30 * time.Second)
	l.Allow("busy") // refreshes lastUsed
	c.advance(30 * time.Second)

	if removed := l.Sweep(); removed != 0 {
		t.Fatalf("sweep removed %d, want 0 for a caller active within the TTL", removed)
	}
	if l.Tracked() != 1 {
		t.Fatalf("tracked=%d, want 1", l.Tracked())
	}
}

func TestKeyedLimiterAllowN(t *testing.T) {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: 1, Burst: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !l.AllowN("door", 5) {
		t.Fatal("AllowN(5) against a burst of 5 should succeed")
	}
	if l.AllowN("door", 1) {
		t.Fatal("bucket should be empty after consuming the full burst")
	}
}

func TestKeyedLimiterConcurrentAllow(t *testing.T) {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: 1000, Burst: 1000})
	if err != nil {
		t.Fatal(err)
	}

	const keys, perKey, burst = 8, 200, 1000
	var wg sync.WaitGroup
	var total atomic.Int64
	for k := 0; k < keys; k++ {
		for i := 0; i < perKey; i++ {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				if l.Allow(string(rune('a' + k))) {
					total.Add(1)
				}
			}(k)
		}
	}
	wg.Wait()

	// No bucket may exceed its configured burst, which is the invariant a
	// concurrent Allow implementation can violate by double-spending. Every
	// goroutine starts at roughly the same instant, so no refill can excuse an
	// excess and the exact bound is assertable rather than approximate.
	if got := total.Load(); got > keys*burst {
		t.Fatalf("allowed %d requests, above the %d the %d buckets could hold", got, keys*burst, keys)
	}
	if l.Tracked() > keys {
		t.Fatalf("tracked=%d, want at most %d distinct keys", l.Tracked(), keys)
	}
}

func TestKeyedLimiterReset(t *testing.T) {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: 1, Burst: 1, MaxKeys: 1})
	if err != nil {
		t.Fatal(err)
	}
	l.Allow("a")
	l.Allow("b")
	l.Reset()

	if l.Tracked() != 0 {
		t.Fatalf("tracked=%d after reset, want 0", l.Tracked())
	}
	if l.Overflowed() != 0 {
		t.Fatalf("overflow counter=%d after reset, want 0", l.Overflowed())
	}
	if !l.Allow("a") {
		t.Fatal("a caller should have a full bucket after reset")
	}
}
