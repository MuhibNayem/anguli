package clients

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"finger-scanner/pkg/resilience"
)

// Breakers holds one circuit breaker per downstream dependency.
//
// Why per-dependency rather than one shared breaker: a single shared breaker
// lets one sick service disconnect the gateway from the two that are healthy.
// Naming them separately means a policy-service outage degrades policy checks
// while biometric matching keeps working.
type Breakers struct {
	biometrics *resilience.Breaker
	policy     *resilience.Breaker
	edge       *resilience.Breaker
	retry      resilience.RetryConfig
}

// NewBreakers builds a breaker set from configuration.
func NewBreakers(cfg BreakerConfig) (*Breakers, error) {
	bc := cfg.Breaker
	if bc.FailureThreshold <= 0 {
		bc.FailureThreshold = 5
	}
	if bc.FailureWindow <= 0 {
		bc.FailureWindow = 30 * time.Second
	}
	if bc.OpenTimeout <= 0 {
		bc.OpenTimeout = 10 * time.Second
	}
	if bc.HalfOpenMaxCalls <= 0 {
		bc.HalfOpenMaxCalls = 1
	}
	if bc.SuccessThreshold <= 0 {
		bc.SuccessThreshold = 2
	}

	rc := cfg.Retry
	if rc.MaxAttempts <= 0 {
		rc = resilience.DefaultRetryConfig()
	}

	mk := func() (*resilience.Breaker, error) {
		return resilience.NewBreaker(resilience.BreakerConfig{
			FailureThreshold: bc.FailureThreshold,
			FailureWindow:    bc.FailureWindow,
			OpenTimeout:      bc.OpenTimeout,
			HalfOpenMaxCalls: bc.HalfOpenMaxCalls,
			SuccessThreshold: bc.SuccessThreshold,
			Now:              bc.Now,
		})
	}

	bio, err := mk()
	if err != nil {
		return nil, fmt.Errorf("biometrics breaker: %w", err)
	}
	pol, err := mk()
	if err != nil {
		return nil, fmt.Errorf("policy breaker: %w", err)
	}
	edg, err := mk()
	if err != nil {
		return nil, fmt.Errorf("edge breaker: %w", err)
	}

	return &Breakers{biometrics: bio, policy: pol, edge: edg, retry: rc}, nil
}

// BreakerConfig configures the downstream breaker set.
type BreakerConfig struct {
	Breaker resilience.BreakerConfig
	Retry   resilience.RetryConfig
}

// Biometrics, Policy and Edge expose the individual breakers for metrics.
func (b *Breakers) Biometrics() *resilience.Breaker { return b.biometrics }
func (b *Breakers) Policy() *resilience.Breaker     { return b.policy }
func (b *Breakers) Edge() *resilience.Breaker       { return b.edge }

// All returns every breaker with its metric label, for publishing.
func (b *Breakers) All() map[string]*resilience.Breaker {
	return map[string]*resilience.Breaker{
		"biometric-service":     b.biometrics,
		"access-policy-service": b.policy,
		"edge-gateway-service":  b.edge,
	}
}

// WhichDownstream identifies a dependency for breaker selection.
type WhichDownstream int

const (
	DownstreamBiometrics WhichDownstream = iota
	DownstreamPolicy
	DownstreamEdge
)

func (b *Breakers) breakerFor(w WhichDownstream) *resilience.Breaker {
	switch w {
	case DownstreamPolicy:
		return b.policy
	case DownstreamEdge:
		return b.edge
	default:
		return b.biometrics
	}
}

// IsRetryable classifies a gRPC error as worth retrying.
//
// Retrying a semantic failure is pure waste and, on a biometric check, actively
// harmful: it burns the reader's occupancy budget re-running a match that will
// return the same answer. Only transport-level and server-side conditions
// qualify.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		// Non-gRPC error: assume it is a local programming bug, not transient.
		return false
	}
	switch st.Code() {
	case codes.Unavailable,
		codes.DeadlineExceeded,
		codes.ResourceExhausted,
		codes.Aborted,
		codes.Internal:
		return true
	default:
		// InvalidArgument, NotFound, PermissionDenied, Unauthenticated,
		// AlreadyExists, FailedPrecondition and the rest are deterministic:
		// the same call produces the same failure.
		return false
	}
}

// Call runs a downstream RPC through its circuit breaker, retrying transient
// failures with exponential backoff and jitter.
//
// Order matters: the breaker gate is checked BEFORE the retry loop, so a
// dependency that is already known to be down is not contacted even once. The
// alternative - retrying and letting the breaker notice afterwards - multiplies
// load on a service that is already failing.
func (b *Breakers) Call(ctx context.Context, w WhichDownstream, fn func(context.Context) error) error {
	br := b.breakerFor(w)

	cfg := b.retry
	cfg.RetryIf = func(err error) bool { return IsRetryable(err) }

	return br.DoWithRetry(ctx, cfg, fn)
}

// Observe publishes every breaker's state into the given metrics registry.
func (b *Breakers) Observe(m *resilience.Metrics) {
	if m == nil {
		return
	}
	for name, br := range b.All() {
		m.ObserveBreaker(name, br)
	}
}
