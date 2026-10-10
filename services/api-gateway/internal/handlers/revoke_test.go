package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
)

// stubRevokeBiometrics records what the gateway asked the biometric service to
// revoke.
type stubRevokeBiometrics struct {
	biometricsv1.BiometricsServiceClient
	last  *biometricsv1.RevokeFingerprintRequest
	calls int
	err   error
}

func (s *stubRevokeBiometrics) RevokeFingerprint(
	_ context.Context, in *biometricsv1.RevokeFingerprintRequest, _ ...grpc.CallOption,
) (*biometricsv1.RevokeFingerprintResponse, error) {
	s.calls++
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &biometricsv1.RevokeFingerprintResponse{Revoked: true, EmployeeId: in.EmployeeId}, nil
}

// stubRevokeEdge records what the gateway told the edge, which is the part of
// offboarding that actually stops a cached copy from matching.
type stubRevokeEdge struct {
	edgegatewayv1.EdgeGatewayServiceClient
	last  *edgegatewayv1.SyncFacilityRosterRequest
	calls int
	err   error
}

func (s *stubRevokeEdge) SyncFacilityRoster(
	_ context.Context, in *edgegatewayv1.SyncFacilityRosterRequest, _ ...grpc.CallOption,
) (*edgegatewayv1.SyncFacilityRosterResponse, error) {
	s.calls++
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &edgegatewayv1.SyncFacilityRosterResponse{Success: true, SyncedCount: 1}, nil
}

func newRevokeFixture(bio *stubRevokeBiometrics, edge *stubRevokeEdge) *handlers.GatewayHandler {
	return handlers.NewGatewayHandler(&clients.ServiceClients{
		BiometricsClient:  bio,
		EdgeGatewayClient: edge,
	}, nil)
}

// TestHandleRevokeTemplate_DeactivatesTheEdge is the assertion that matters
// most.
//
// Revoking centrally is not sufficient on its own. Every edge node caches the
// templates it is given, and that cache is not remotely recallable: an edge
// that is never told keeps matching the template it already holds. So the
// gateway has to push the deactivation explicitly, with IsActive false - and
// nothing else in the system does that.
func TestHandleRevokeTemplate_DeactivatesTheEdge(t *testing.T) {
	bio := &stubRevokeBiometrics{}
	edge := &stubRevokeEdge{}
	h := newRevokeFixture(bio, edge)

	rec := do(t, h.HandleRevokeTemplate, http.MethodPost, "/api/v1/biometrics/revoke",
		`{"employee_id":"EMP-9","position":2,"reason":"OFFBOARDED"}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	if bio.calls != 1 {
		t.Fatalf("biometric service called %d times, want 1", bio.calls)
	}
	if bio.last.GetEmployeeId() != "EMP-9" {
		t.Fatalf("revoked employee = %q, want EMP-9", bio.last.GetEmployeeId())
	}
	if bio.last.GetReason() != "OFFBOARDED" {
		t.Fatalf("reason = %q, want OFFBOARDED", bio.last.GetReason())
	}

	if edge.calls != 1 {
		t.Fatalf("edge called %d times, want 1; the cached edge copy must be deactivated", edge.calls)
	}
	items := edge.last.GetItems()
	if len(items) != 1 {
		t.Fatalf("edge sync carried %d items, want 1", len(items))
	}
	if items[0].GetIsActive() {
		t.Fatal("edge was told the employee is still ACTIVE; the edge will keep matching them")
	}
	if items[0].GetEmployeeId() != "EMP-9" {
		t.Fatalf("edge told about %q, want EMP-9", items[0].GetEmployeeId())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if body["edge_synced"] != true {
		t.Fatalf("edge_synced = %v, want true", body["edge_synced"])
	}
}

// TestHandleRevokeTemplate_ReportsEdgeFailure is the case that would otherwise
// be hidden. A successful central revoke with a failed edge sync leaves the
// person denied centrally but still matchable at the edge. That is a partial
// offboarding, and reporting it as success is how someone leaves a building
// thinking they revoked access that is still live.
func TestHandleRevokeTemplate_ReportsEdgeFailure(t *testing.T) {
	bio := &stubRevokeBiometrics{}
	edge := &stubRevokeEdge{err: status.Error(codes.Unavailable, "edge offline")}
	h := newRevokeFixture(bio, edge)

	rec := do(t, h.HandleRevokeTemplate, http.MethodPost, "/api/v1/biometrics/revoke",
		`{"employee_id":"EMP-9","position":1,"reason":"OFFBOARDED"}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; the central revoke succeeded so 200 is right, "+
			"but the edge failure must be visible in the body. body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["edge_synced"] != false {
		t.Fatalf("edge_synced = %v, want false when the edge could not be told", body["edge_synced"])
	}
	if body["revoked"] != true {
		t.Fatalf("revoked = %v, want true; the central revoke did succeed", body["revoked"])
	}
}

func TestHandleRevokeTemplate_RejectsBadInput(t *testing.T) {
	bio := &stubRevokeBiometrics{}
	edge := &stubRevokeEdge{}
	h := newRevokeFixture(bio, edge)

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"wrong method", http.MethodGet, "/api/v1/biometrics/revoke", "", http.StatusMethodNotAllowed},
		{"malformed json", http.MethodPost, "/api/v1/biometrics/revoke", "{nope", http.StatusBadRequest},
		{"missing employee", http.MethodPost, "/api/v1/biometrics/revoke", `{"position":1}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h.HandleRevokeTemplate, tc.method, tc.path, tc.body, nil)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
			if bio.calls != 0 {
				t.Fatalf("biometric service was called %d times for an invalid request", bio.calls)
			}
		})
	}
}

// TestHandleRevokeTemplate_DefaultsMissingReason pins the deliberate choice to
// record an unlabelled revocation rather than refuse it.
//
// Rejecting the request would leave the employee enrolled. A vague audit
// reason is a much smaller problem than a terminated employee who still opens
// the door, so the handler substitutes UNSPECIFIED and proceeds.
func TestHandleRevokeTemplate_DefaultsMissingReason(t *testing.T) {
	bio := &stubRevokeBiometrics{}
	edge := &stubRevokeEdge{}
	h := newRevokeFixture(bio, edge)

	rec := do(t, h.HandleRevokeTemplate, http.MethodPost, "/api/v1/biometrics/revoke",
		`{"employee_id":"EMP-9","position":1,"reason":"   "}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; a blank reason must not block offboarding", rec.Code)
	}
	if bio.last.GetReason() != "UNSPECIFIED" {
		t.Fatalf("reason = %q, want UNSPECIFIED", bio.last.GetReason())
	}
}

func TestHandleRevokeTemplate_PropagatesDownstreamError(t *testing.T) {
	bio := &stubRevokeBiometrics{err: errors.New("storage unavailable")}
	edge := &stubRevokeEdge{}
	h := newRevokeFixture(bio, edge)

	rec := do(t, h.HandleRevokeTemplate, http.MethodPost, "/api/v1/biometrics/revoke",
		`{"employee_id":"EMP-9","position":1}`, nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	if edge.calls != 0 {
		t.Fatal("edge was told to deactivate after the central revoke failed")
	}
}

// TestHandleRevokeTemplate_AcceptsDelete documents that both verbs are
// supported, since offboarding is often driven by a DELETE-shaped workflow.
func TestHandleRevokeTemplate_AcceptsDelete(t *testing.T) {
	bio := &stubRevokeBiometrics{}
	edge := &stubRevokeEdge{}
	h := newRevokeFixture(bio, edge)

	rec := do(t, h.HandleRevokeTemplate, http.MethodDelete, "/api/v1/biometrics/revoke",
		`{"employee_id":"EMP-9","position":1}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if bio.calls != 1 {
		t.Fatalf("biometric service called %d times, want 1", bio.calls)
	}
}
