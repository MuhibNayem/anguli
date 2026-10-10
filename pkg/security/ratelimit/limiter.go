package ratelimit

import (
	"sync"
	"time"
)

// TokenBucketLimiter implements a high-throughput, thread-safe token bucket rate limiter.
type TokenBucketLimiter struct {
	rate       float64 // tokens per second
	capacity   float64 // maximum bucket size
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a rate limiter with specified rate (req/sec) and burst capacity.
func NewTokenBucket(rate float64, capacity float64) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity,
		lastRefill: time.Now(),
	}
}

// Allow reports whether a single request is allowed through.
func (tb *TokenBucketLimiter) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if n tokens can be consumed immediately.
func (tb *TokenBucketLimiter) AllowN(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	// Refill tokens based on elapsed time
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}

	return false
}
