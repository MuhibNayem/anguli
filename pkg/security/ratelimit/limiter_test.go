package ratelimit_test

import (
	"testing"
	"time"

	"finger-scanner/pkg/security/ratelimit"
)

func TestTokenBucketLimiter(t *testing.T) {
	// 10 tokens/sec, capacity 2
	limiter := ratelimit.NewTokenBucket(10, 2)

	// Consume capacity
	if !limiter.Allow() {
		t.Errorf("expected first token to be allowed")
	}
	if !limiter.Allow() {
		t.Errorf("expected second token to be allowed")
	}

	// Burst exhausted
	if limiter.Allow() {
		t.Errorf("expected third immediate token to be rejected")
	}

	// Wait for refill (150ms -> 1.5 tokens)
	time.Sleep(150 * time.Millisecond)

	if !limiter.Allow() {
		t.Errorf("expected token to be allowed after refill")
	}
}
