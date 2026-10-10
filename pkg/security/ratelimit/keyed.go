package ratelimit

import (
	"sync"
	"time"
)

// KeyedLimiterConfig configures a KeyedLimiter.
type KeyedLimiterConfig struct {
	// Rate is sustained tokens per second granted to each key.
	Rate float64
	// Burst is the bucket capacity, which is also the largest instantaneous
	// burst a single key may make.
	Burst float64
	// MaxKeys bounds how many distinct keys are tracked at once. Zero selects
	// a default. This is a memory-safety limit, not a tuning knob: an
	// attacker who can vary the key (a spoofable header, say) would otherwise
	// grow this map without bound and turn a rate limiter into the outage.
	MaxKeys int
	// IdleTTL is how long a key with no traffic is kept before it is evicted.
	// Zero selects a default.
	IdleTTL time.Duration
	// Now overrides the clock. Nil uses time.Now. Tests set this so eviction
	// and refill can be exercised without sleeping.
	Now func() time.Time
}

const (
	defaultMaxKeys = 10_000
	defaultIdleTTL = 10 * time.Minute
)

// KeyedLimiter applies an independent token bucket to each caller key.
//
// A single global bucket is the wrong shape for this problem. Every turnstile
// in a building legitimately shares one API key today, so a global limit
// either throttles the whole site or, set high enough to avoid that, stops
// catching anything at all. Bucketing per caller keeps one noisy door from
// consuming everyone else's budget, and it is the granularity at which an
// enumeration attempt becomes attributable.
//
// Memory is bounded by MaxKeys. A key arriving once the table is full is not
// given its own bucket; it draws from a single shared overflow bucket. That is
// deliberate: an attacker minting unique keys is throttled rather than served,
// and legitimate new callers degrade to a shared budget rather than pushing
// everyone else out.
type KeyedLimiter struct {
	rate     float64
	burst    float64
	maxKeys  int
	idleTTL  time.Duration
	now      func() time.Time
	overflow *TokenBucketLimiter

	mu      sync.Mutex
	buckets map[string]*keyedBucket

	// observed counters for tests and metrics.
	overflowed uint64
	evicted    uint64
}

// keyedBucket is one caller's token bucket plus its last-use timestamp.
type keyedBucket struct {
	tokens   float64
	lastUsed time.Time
}

// NewKeyedLimiter builds a KeyedLimiter.
//
// Rate and Burst must be positive: a non-positive rate would silently deny
// every request, which in this platform means locking real employees out of
// doors rather than failing a unit test.
func NewKeyedLimiter(cfg KeyedLimiterConfig) (*KeyedLimiter, error) {
	if cfg.Rate <= 0 {
		return nil, ErrInvalidRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.Rate
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = defaultMaxKeys
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &KeyedLimiter{
		rate:     cfg.Rate,
		burst:    cfg.Burst,
		maxKeys:  cfg.MaxKeys,
		idleTTL:  cfg.IdleTTL,
		now:      cfg.Now,
		overflow: NewTokenBucket(cfg.Rate, cfg.Burst),
		buckets:  make(map[string]*keyedBucket),
	}, nil
}

// Rate reports the configured sustained rate.
func (k *KeyedLimiter) Rate() float64 { return k.rate }

// Burst reports the configured bucket capacity.
func (k *KeyedLimiter) Burst() float64 { return k.burst }

// Allow consumes one token for key, reporting whether the request may proceed.
func (k *KeyedLimiter) Allow(key string) bool {
	return k.AllowN(key, 1)
}

// AllowN consumes n tokens for key.
//
// A key with no bucket and no room for one falls through to the shared
// overflow bucket, so the worst case for a legitimate caller arriving at
// capacity is a shared budget rather than an outright rejection.
func (k *KeyedLimiter) AllowN(key string, n float64) bool {
	now := k.now()

	k.mu.Lock()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			k.sweepLocked(now)
		}
		if len(k.buckets) >= k.maxKeys {
			k.overflowed++
			k.mu.Unlock()
			return k.overflow.AllowN(n)
		}
		b = &keyedBucket{tokens: k.burst, lastUsed: now}
		k.buckets[key] = b
	}

	elapsed := now.Sub(b.lastUsed).Seconds()
	b.lastUsed = now
	b.tokens += elapsed * k.rate
	if b.tokens > k.burst {
		b.tokens = k.burst
	}

	if b.tokens >= n {
		b.tokens -= n
		k.mu.Unlock()
		return true
	}
	k.mu.Unlock()
	return false
}

// Sweep evicts buckets that have been idle longer than IdleTTL and returns how
// many were removed. Calling it on a timer keeps the table proportional to
// active callers rather than to callers seen since the process started.
func (k *KeyedLimiter) Sweep() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.sweepLocked(k.now())
}

func (k *KeyedLimiter) sweepLocked(now time.Time) int {
	cutoff := now.Add(-k.idleTTL)
	removed := 0
	for key, b := range k.buckets {
		if b.lastUsed.Before(cutoff) {
			delete(k.buckets, key)
			removed++
		}
	}
	k.evicted += uint64(removed)
	return removed
}

// Tracked reports how many distinct keys currently hold a bucket.
func (k *KeyedLimiter) Tracked() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}

// Overflowed reports how many requests have been served from the shared
// overflow bucket because the table was full. A non-zero value means the
// MaxKeys bound is being reached, which is an attack signal or a misconfigured
// limit, not a normal condition.
func (k *KeyedLimiter) Overflowed() uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.overflowed
}

// Reset drops every bucket. Used by tests and by administrative reloads.
func (k *KeyedLimiter) Reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.buckets = make(map[string]*keyedBucket)
	k.overflow = NewTokenBucket(k.rate, k.burst)
	k.overflowed = 0
}
