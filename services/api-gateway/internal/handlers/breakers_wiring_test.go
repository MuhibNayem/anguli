package handlers_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"

	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/pkg/resilience"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
)

// These tests exist because the breakers used to be constructed in main.go,
// published to /metrics by a ticker, and never passed to the handler at all.
// Nothing about the wiring was covered, so a complete - green - suite
// coexisted with circuit breakers that could never trip.

// failingEdge always errors, so the breaker has something to observe.
type failingEdge struct {
	edgegatewayv1.EdgeGatewayServiceClient
	err   error
	calls int
}

func (f *failingEdge) ProcessTurnstileScan(_ context.Context, _ *edgegatewayv1.ProcessTurnstileScanRequest, _ ...grpc.CallOption) (*edgegatewayv1.ProcessTurnstileScanResponse, error) {
	f.calls++
	return nil, f.err
}

// trippable builds breakers that open after a single failure and stay open
// long enough for the assertion to be deterministic.
func trippable() *clients.Breakers {
	b, err := clients.NewBreakers(clients.BreakerConfig{
		Breaker: resilience.BreakerConfig{
			FailureThreshold: 1,
			FailureWindow:    time.Minute,
			OpenTimeout:      time.Hour, // never half-open during this test
			SuccessThreshold: 1,
		},
		Retry: resilience.RetryConfig{MaxAttempts: 1},
	})
	if err != nil {
		panic(err)
	}
	return b
}

func TestBreakersAreActuallyWiredIntoTheHandler(t *testing.T) {
	edge := &failingEdge{err: errors.New("edge unreachable")}

	b := trippable()
	h := handlers.NewGatewayHandlerWithBreakers(&clients.ServiceClients{
		BiometricsClient:   &stubBiometrics{},
		AccessPolicyClient: &stubPolicy{},
		EdgeGatewayClient:  edge,
	}, b, nil)

	// An authenticated reader request that fails downstream should trip the
	// edge breaker.
	body := `{"turnstile_id":"t","zone_id":"z","employee_id":"EMP-1"}`
	hdr := map[string]string{"X-Reader-ID": "reader-07"}

	rec := do(t, h.HandleDoorScan, http.MethodPost, "/scan", body, hdr)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("first call status = %d; want 500 while the dependency is failing", rec.Code)
	}
	callsAfterFirst := edge.calls

	// The breaker is now open. The next request must be refused WITHOUT
	// touching the dependency - that is the whole point of a circuit breaker,
	// and the behaviour that was previously absent entirely.
	rec2 := do(t, h.HandleDoorScan, http.MethodPost, "/scan", body, hdr)
	if edge.calls != callsAfterFirst {
		t.Errorf("the downstream service was called %d more time(s) while the breaker was open; "+
			"the breaker is not gating traffic", edge.calls-callsAfterFirst)
	}
	if rec2.Code == http.StatusOK {
		t.Error("a request was granted while the dependency breaker was open")
	}
}

// A handler built without breakers must still work - that is what keeps the
// existing unit tests and any dependency-less wiring valid.
func TestHandlerWithoutBreakersStillServes(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan",
		`{"turnstile_id":"t","zone_id":"z","employee_id":"EMP-1"}`,
		map[string]string{"X-Reader-ID": "r7"})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; a breaker-less handler should pass straight through: %s", rec.Code, rec.Body.String())
	}
}
