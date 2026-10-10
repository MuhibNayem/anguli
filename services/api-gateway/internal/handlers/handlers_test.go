package handlers_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
)

type mockEdgeGatewayClient struct {
	edgegatewayv1.EdgeGatewayServiceClient
}

func (m *mockEdgeGatewayClient) ProcessTurnstileScan(ctx context.Context, in *edgegatewayv1.ProcessTurnstileScanRequest, opts ...grpc.CallOption) (*edgegatewayv1.ProcessTurnstileScanResponse, error) {
	return &edgegatewayv1.ProcessTurnstileScanResponse{
		IsAccessGranted:        true,
		Decision:               accesscontrolv1.AccessDecision_ACCESS_DECISION_GRANTED,
		MatchedEmployeeId:      in.EmployeeId,
		MatchScore:             95.0,
		Reason:                 "Access granted",
		RelayStrikeDurationMs:  2500,
		TotalLatencyMs:         45,
		ProcessedOffline:       false,
	}, nil
}

func TestHandleDoorScan_C5_UntrustedIdentityClaimRejected(t *testing.T) {
	cl := &clients.ServiceClients{
		BiometricsClient:   biometricsv1.NewBiometricsServiceClient(nil),
		AccessPolicyClient: accesscontrolv1.NewAccessPolicyServiceClient(nil),
		EdgeGatewayClient:  &mockEdgeGatewayClient{},
	}
	h := handlers.NewGatewayHandler(cl, nil)

	// Caller attempts 1:1 match by supplying employee_id WITHOUT reader auth headers
	payload := []byte(`{"turnstile_id":"turnstile-01","zone_id":"zone-main-gate","direction":1,"employee_id":"EMP-VICTIM-99"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/door/scan", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	h.HandleDoorScan(rec, req)

	// C5: Untrusted claim without reader authentication MUST be rejected
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for untrusted identity claim, got %d", rec.Code)
	}

	// Now try with authenticated reader header
	reqAuth := httptest.NewRequest(http.MethodPost, "/api/v1/door/scan", bytes.NewReader(payload))
	reqAuth.Header.Set("X-Reader-Token", "valid-reader-secret")
	recAuth := httptest.NewRecorder()

	h.HandleDoorScan(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authenticated reader, got %d", recAuth.Code)
	}
}
