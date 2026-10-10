package clients

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"finger-scanner/pkg/resilience"
)

func TestIsRetryable_ClassifiesGRPCCodes(t *testing.T) {
	retryable := []codes.Code{
		codes.Unavailable,
		codes.DeadlineExceeded,
		codes.ResourceExhausted,
		codes.Aborted,
		codes.Internal,
	}
	for _, c := range retryable {
		err := status.Error(c, "x")
		if !IsRetryable(err) {
			t.Errorf("IsRetryable(%s) = false; want true", c)
		}
	}

	// These are deterministic: the identical call yields the identical failure,
	// so retrying only burns the reader's occupancy budget.
	permanent := []codes.Code{
		codes.InvalidArgument,
		codes.NotFound,
		codes.PermissionDenied,
		codes.Unauthenticated,
		codes.AlreadyExists,
		codes.FailedPrecondition,
		codes.OK,
	}
	for _, c := range permanent {
		err := status.Error(c, "x")
		if IsRetryable(err) {
			t.Errorf("IsRetryable(%s) = true; want false", c)
		}
	}

	if IsRetryable(nil) {
		t.Error("IsRetryable(nil) = true")
	}
	// A non-gRPC error is a local bug, not a transient condition.
	if IsRetryable(errors.New("boom")) {
		t.Error("IsRetryable(non-gRPC error) = true; want false")
	}
}

func newTestBreakers(t *testing.T) *Breakers {
	t.Helper()
	b, err := NewBreakers(BreakerConfig{
		Breaker: resilience.BreakerConfig{
			FailureThreshold: 3,
			FailureWindow:    time.Minute,
			OpenTimeout:      time.Hour, // stay open for the duration of the test
			HalfOpenMaxCalls: 1,
			SuccessThreshold: 1,
		},
		Retry: resilience.RetryConfig{
			MaxAttempts: 1, // isolate breaker behaviour from retry behaviour
			BaseDelay:   time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBreakers_CallOpensAfterThreshold(t *testing.T) {
	b := newTestBreakers(t)
	var calls atomic.Int64

	for i := 0; i < 3; i++ {
		_ = b.Call(context.Background(), DownstreamBiometrics, func(context.Context) error {
			calls.Add(1)
			return status.Error(codes.Unavailable, "down")
		})
	}
	if b.Biometrics().State() != resilience.StateOpen {
		t.Fatalf("breaker state = %s after 3 failures; want open", b.Biometrics().State())
	}

	before := calls.Load()
	err := b.Call(context.Background(), DownstreamBiometrics, func(context.Context) error {
		calls.Add(1)
		return nil
	})
	if !errors.Is(err, resilience.ErrBreakerOpen) {
		t.Fatalf("Call = %v; want ErrBreakerOpen", err)
	}
	if calls.Load() != before {
		t.Errorf("dependency was called %d extra times while the breaker was open", calls.Load()-before)
	}
}

func TestBreakers_AreIndependentPerDependency(t *testing.T) {
	b := newTestBreakers(t)

	// Wedge the policy dependency only.
	for i := 0; i < 3; i++ {
		_ = b.Call(context.Background(), DownstreamPolicy, func(context.Context) error {
			return status.Error(codes.Unavailable, "policy down")
		})
	}
	if b.Policy().State() != resilience.StateOpen {
		t.Fatal("policy breaker did not open")
	}

	// A shared breaker would now reject biometrics too. It must not.
	var reached atomic.Bool
	err := b.Call(context.Background(), DownstreamBiometrics, func(context.Context) error {
		reached.Store(true)
		return nil
	})
	if err != nil {
		t.Fatalf("biometrics call failed while only the policy breaker was open: %v", err)
	}
	if !reached.Load() {
		t.Error("biometrics dependency was not reached; breakers are not independent")
	}
	if b.Biometrics().State() != resilience.StateClosed {
		t.Errorf("biometrics breaker = %s; want closed", b.Biometrics().State())
	}

	// And the wedged dependency must still be shed.
	if err := b.Call(context.Background(), DownstreamPolicy, func(context.Context) error {
		return nil
	}); !errors.Is(err, resilience.ErrBreakerOpen) {
		t.Errorf("policy Call = %v; want ErrBreakerOpen", err)
	}
}

func TestBreakers_CallRetriesTransientThenSucceeds(t *testing.T) {
	b, err := NewBreakers(BreakerConfig{
		Breaker: resilience.BreakerConfig{
			FailureThreshold: 10, FailureWindow: time.Minute,
			OpenTimeout: time.Hour, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		},
		Retry: resilience.RetryConfig{
			MaxAttempts: 3, BaseDelay: time.Millisecond,
			MaxDelay: 2 * time.Millisecond,
			Sleep:    func(context.Context, time.Duration) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int64
	err = b.Call(context.Background(), DownstreamEdge, func(context.Context) error {
		if calls.Add(1) < 3 {
			return status.Error(codes.Unavailable, "flaky")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Call = %v; want success after retries", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d; want 3", calls.Load())
	}
	if b.Edge().State() != resilience.StateClosed {
		t.Errorf("breaker = %s after eventual success; want closed", b.Edge().State())
	}
}

func TestBreakers_CallDoesNotRetryPermanentError(t *testing.T) {
	b, err := NewBreakers(BreakerConfig{
		Breaker: resilience.BreakerConfig{
			FailureThreshold: 10, FailureWindow: time.Minute,
			OpenTimeout: time.Hour, HalfOpenMaxCalls: 1, SuccessThreshold: 1,
		},
		Retry: resilience.RetryConfig{
			MaxAttempts: 5, BaseDelay: time.Millisecond,
			Sleep: func(context.Context, time.Duration) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int64
	err = b.Call(context.Background(), DownstreamBiometrics, func(context.Context) error {
		calls.Add(1)
		return status.Error(codes.InvalidArgument, "malformed request")
	})
	if err == nil {
		t.Fatal("Call = nil; want the InvalidArgument error")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d; a deterministic failure must not be retried", calls.Load())
	}
}

func TestBreakers_CallHonoursContextCancellation(t *testing.T) {
	b := newTestBreakers(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls atomic.Int64
	err := b.Call(ctx, DownstreamBiometrics, func(context.Context) error {
		calls.Add(1)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Call = %v; want context.Canceled", err)
	}
	if calls.Load() != 0 {
		t.Errorf("dependency called %d times with a cancelled context", calls.Load())
	}
	if b.Biometrics().State() != resilience.StateClosed {
		t.Error("a cancelled call must not trip the breaker")
	}
}

func TestNewBreakers_Defaults(t *testing.T) {
	b, err := NewBreakers(BreakerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for name, br := range b.All() {
		if br == nil {
			t.Fatalf("%s breaker is nil", name)
		}
		if br.State() != resilience.StateClosed {
			t.Errorf("%s breaker starts %s; want closed", name, br.State())
		}
	}
}

func TestBreakers_ObserveDoesNotPanic(t *testing.T) {
	b := newTestBreakers(t)
	m := resilience.NewMetrics()
	b.Observe(m)
	b.Observe(nil) // must be a safe no-op
}
