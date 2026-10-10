package handlers_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
)

// ---------------------------------------------------------------------------
// Mock clients
// ---------------------------------------------------------------------------

type stubBiometrics struct {
	biometricsv1.BiometricsServiceClient

	enrollResp *biometricsv1.EnrollFingerprintResponse
	enrollErr  error
	verifyResp *biometricsv1.VerifyFingerprintResponse
	verifyErr  error

	lastEnroll *biometricsv1.EnrollFingerprintRequest
	lastVerify *biometricsv1.VerifyFingerprintRequest
}

func (s *stubBiometrics) EnrollFingerprint(_ context.Context, in *biometricsv1.EnrollFingerprintRequest, _ ...grpc.CallOption) (*biometricsv1.EnrollFingerprintResponse, error) {
	s.lastEnroll = in
	if s.enrollErr != nil {
		return nil, s.enrollErr
	}
	if s.enrollResp != nil {
		return s.enrollResp, nil
	}
	return &biometricsv1.EnrollFingerprintResponse{
		TemplateId: "tmpl-1", MinutiaeCount: 20, NfiqQualityScore: 78,
	}, nil
}

func (s *stubBiometrics) VerifyFingerprint(_ context.Context, in *biometricsv1.VerifyFingerprintRequest, _ ...grpc.CallOption) (*biometricsv1.VerifyFingerprintResponse, error) {
	s.lastVerify = in
	if s.verifyErr != nil {
		return nil, s.verifyErr
	}
	if s.verifyResp != nil {
		return s.verifyResp, nil
	}
	return &biometricsv1.VerifyFingerprintResponse{
		IsMatch: true, Score: 88.5, MatchedCylinders: 31, MatchingTimeUs: 1200,
	}, nil
}

func (s *stubBiometrics) GetTemplate(_ context.Context, _ *biometricsv1.GetTemplateRequest, _ ...grpc.CallOption) (*biometricsv1.GetTemplateResponse, error) {
	return &biometricsv1.GetTemplateResponse{Found: false}, nil
}

type stubEdge struct {
	edgegatewayv1.EdgeGatewayServiceClient

	scanResp   *edgegatewayv1.ProcessTurnstileScanResponse
	scanErr    error
	statusResp *edgegatewayv1.GetTurnstileStatusResponse
	statusErr  error

	lastScan *edgegatewayv1.ProcessTurnstileScanRequest
}

func (s *stubEdge) ProcessTurnstileScan(_ context.Context, in *edgegatewayv1.ProcessTurnstileScanRequest, _ ...grpc.CallOption) (*edgegatewayv1.ProcessTurnstileScanResponse, error) {
	s.lastScan = in
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	if s.scanResp != nil {
		return s.scanResp, nil
	}
	return &edgegatewayv1.ProcessTurnstileScanResponse{
		IsAccessGranted: true,
		Decision:        accesscontrolv1.AccessDecision_ACCESS_DECISION_GRANTED,
	}, nil
}

func (s *stubEdge) GetTurnstileStatus(_ context.Context, _ *edgegatewayv1.GetTurnstileStatusRequest, _ ...grpc.CallOption) (*edgegatewayv1.GetTurnstileStatusResponse, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	if s.statusResp != nil {
		return s.statusResp, nil
	}
	return &edgegatewayv1.GetTurnstileStatusResponse{
		Status: &edgegatewayv1.TurnstileStatus{
			TurnstileId: "turnstile-lane-01", IsOnline: true, LocalRosterCount: 7,
		},
	}, nil
}

func (s *stubEdge) SyncFacilityRoster(_ context.Context, _ *edgegatewayv1.SyncFacilityRosterRequest, _ ...grpc.CallOption) (*edgegatewayv1.SyncFacilityRosterResponse, error) {
	return &edgegatewayv1.SyncFacilityRosterResponse{Success: true, SyncedCount: 1}, nil
}

type stubPolicy struct {
	accesscontrolv1.AccessPolicyServiceClient

	resetResp *accesscontrolv1.ResetAntiPassbackResponse
	resetErr  error
}

func (s *stubPolicy) ResetAntiPassback(_ context.Context, _ *accesscontrolv1.ResetAntiPassbackRequest, _ ...grpc.CallOption) (*accesscontrolv1.ResetAntiPassbackResponse, error) {
	if s.resetErr != nil {
		return nil, s.resetErr
	}
	if s.resetResp != nil {
		return s.resetResp, nil
	}
	return &accesscontrolv1.ResetAntiPassbackResponse{Success: true, Message: "APB reset"}, nil
}

type fixture struct {
	h    *handlers.GatewayHandler
	bio  *stubBiometrics
	edge *stubEdge
	pol  *stubPolicy
}

func newFixture() *fixture {
	f := &fixture{
		bio:  &stubBiometrics{},
		edge: &stubEdge{},
		pol:  &stubPolicy{},
	}
	f.h = handlers.NewGatewayHandler(&clients.ServiceClients{
		BiometricsClient:   f.bio,
		AccessPolicyClient: f.pol,
		EdgeGatewayClient:  f.edge,
	}, nil)
	return f
}

func do(t *testing.T, h http.HandlerFunc, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Method guards
// ---------------------------------------------------------------------------

func TestHandlers_MethodNotAllowed(t *testing.T) {
	f := newFixture()
	for name, h := range map[string]http.HandlerFunc{
		"enroll": f.h.HandleEnroll,
		"verify": f.h.HandleVerify,
		"scan":   f.h.HandleDoorScan,
		"reset":  f.h.HandleResetAPB,
	} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			rec := do(t, h, method, "/x", "", nil)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d; want 405", name, method, rec.Code)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

func TestHandleEnroll_Success(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleEnroll, http.MethodPost, "/api/v1/biometrics/enroll",
		`{"employee_id":"EMP-1","full_name":"Ada","position":1}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200: %s", rec.Code, rec.Body.String())
	}
	if f.bio.lastEnroll == nil {
		t.Fatal("downstream was never called")
	}
	if f.bio.lastEnroll.EmployeeId != "EMP-1" {
		t.Errorf("EmployeeId = %q", f.bio.lastEnroll.EmployeeId)
	}
	// M13: with no explicit dimensions the handler must fall back to 120x120.
	if f.bio.lastEnroll.Width != 120 || f.bio.lastEnroll.Height != 120 {
		t.Errorf("dimensions = %dx%d; want 120x120 fallback", f.bio.lastEnroll.Width, f.bio.lastEnroll.Height)
	}
}

func TestHandleEnroll_HonoursExplicitDimensions(t *testing.T) {
	f := newFixture()
	img := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 200*200))
	rec := do(t, f.h.HandleEnroll, http.MethodPost, "/api/v1/biometrics/enroll",
		`{"employee_id":"EMP-2","image_base64":"`+img+`","width":200,"height":200}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if f.bio.lastEnroll.Width != 200 || f.bio.lastEnroll.Height != 200 {
		t.Errorf("dimensions = %dx%d; want 200x200", f.bio.lastEnroll.Width, f.bio.lastEnroll.Height)
	}
	if len(f.bio.lastEnroll.ImageRawGray) != 200*200 {
		t.Errorf("decoded image length = %d; want 40000", len(f.bio.lastEnroll.ImageRawGray))
	}
}

func TestHandleEnroll_RejectsBadInput(t *testing.T) {
	f := newFixture()
	cases := map[string]struct {
		body string
		want int
	}{
		"malformed json":   {`{"employee_id":`, http.StatusBadRequest},
		"missing employee": {`{"full_name":"Nobody"}`, http.StatusBadRequest},
		"invalid base64":   {`{"employee_id":"E","image_base64":"!!!not-base64!!!"}`, http.StatusBadRequest},
		"empty body":       {``, http.StatusBadRequest},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, f.h.HandleEnroll, http.MethodPost, "/enroll", c.body, nil)
			if rec.Code != c.want {
				t.Errorf("status = %d; want %d: %s", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

func TestHandleEnroll_PropagatesDownstreamError(t *testing.T) {
	f := newFixture()
	f.bio.enrollErr = status.Error(codes.InvalidArgument, "quality gate rejected")
	rec := do(t, f.h.HandleEnroll, http.MethodPost, "/enroll", `{"employee_id":"EMP-3"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("quality gate rejected")) {
		t.Errorf("body = %s; want the downstream reason surfaced", rec.Body.String())
	}
}

func TestHandleEnroll_RejectsOversizedBody(t *testing.T) {
	f := newFixture()
	// 11MB of base64 exceeds the 10MB bound the handler installs.
	huge := `{"employee_id":"E","image_base64":"` +
		string(bytes.Repeat([]byte{'A'}, 11<<20)) + `"}`
	rec := do(t, f.h.HandleEnroll, http.MethodPost, "/enroll", huge, nil)
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d; want the oversized body rejected", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func TestHandleVerify_Success(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleVerify, http.MethodPost, "/verify",
		`{"employee_id":"EMP-1","position":1}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["is_match"] != true {
		t.Errorf("is_match = %v; want true", body["is_match"])
	}
	if body["score"] != 88.5 {
		t.Errorf("score = %v; want 88.5", body["score"])
	}
}

func TestHandleVerify_RejectsBadInput(t *testing.T) {
	f := newFixture()
	for name, body := range map[string]string{
		"malformed json": `{"employee_id":`,
		"invalid base64": `{"employee_id":"E","image_base64":"###"}`,
	} {
		rec := do(t, f.h.HandleVerify, http.MethodPost, "/verify", body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d; want 400", name, rec.Code)
		}
	}
}

func TestHandleVerify_DownstreamNotFoundIs404(t *testing.T) {
	f := newFixture()
	f.bio.verifyErr = status.Error(codes.NotFound, "not enrolled")
	rec := do(t, f.h.HandleVerify, http.MethodPost, "/verify", `{"employee_id":"NOBODY"}`, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Door scan
// ---------------------------------------------------------------------------

func TestHandleDoorScan_DefaultsAreApplied(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan", `{}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if f.edge.lastScan.TurnstileId != "turnstile-lane-01" {
		t.Errorf("TurnstileId = %q; want the default lane", f.edge.lastScan.TurnstileId)
	}
	if f.edge.lastScan.ZoneId != "zone-main-gate" {
		t.Errorf("ZoneId = %q; want the default zone", f.edge.lastScan.ZoneId)
	}
	if f.edge.lastScan.Direction != accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY {
		t.Errorf("Direction = %v; want ENTRY as the default", f.edge.lastScan.Direction)
	}
}

// TestHandleDoorScan_C5EveryClaimPathIsGated walks each way a caller can try
// to assert an identity, and requires an authenticated channel or a physical
// badge for all of them. This is the control that stops a 1:1 claim from
// becoming an unlock.
func TestHandleDoorScan_C5EveryClaimPathIsGated(t *testing.T) {
	f := newFixture()
	body := `{"turnstile_id":"t","zone_id":"z","employee_id":"EMP-VICTIM"}`

	untrusted := map[string]map[string]string{
		"no headers at all":      {},
		"empty-valued token":     {"X-Reader-Token": ""},
		"empty-valued reader id": {"X-Reader-ID": ""},
		"empty-valued api key":   {"X-API-Key": ""},
		"blank token":            {"X-Reader-Token": "   "},
	}
	for name, hdr := range untrusted {
		t.Run("rejects "+name, func(t *testing.T) {
			rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan", body, hdr)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d; want 403 for %s", rec.Code, name)
			}
		})
	}

	trusted := map[string]map[string]string{
		"reader token": {"X-Reader-Token": "valid-reader-secret"},
		"reader id":    {"X-Reader-ID": "reader-07"},
		"api key":      {"X-API-Key": "k"},
	}
	for name, hdr := range trusted {
		t.Run("allows "+name, func(t *testing.T) {
			rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan", body, hdr)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d; want 200 for %s: %s", rec.Code, name, rec.Body.String())
			}
		})
	}
}

func TestHandleDoorScan_BadgeCredentialIsTrusted(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan",
		`{"employee_id":"EMP-1","credential_card_id":"BADGE-77"}`, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; a physical badge is a trusted credential", rec.Code)
	}
}

func TestHandleDoorScan_EdgeErrorIs500(t *testing.T) {
	f := newFixture()
	f.edge.scanErr = errors.New("edge offline")
	rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan", `{}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("edge gateway scan error")) {
		t.Errorf("body = %s; want it prefixed for triage", rec.Body.String())
	}
}

func TestHandleDoorScan_RejectsBadJSON(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleDoorScan, http.MethodPost, "/scan", `{`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Status, APB reset, health
// ---------------------------------------------------------------------------

func TestHandleDoorStatus_DefaultsAndSuccess(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleDoorStatus, http.MethodGet, "/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleDoorStatus_EdgeErrorIs500(t *testing.T) {
	f := newFixture()
	f.edge.statusErr = errors.New("unreachable")
	rec := do(t, f.h.HandleDoorStatus, http.MethodGet, "/status", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", rec.Code)
	}
}

func TestHandleResetAPB_Success(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleResetAPB, http.MethodPost, "/reset",
		`{"employee_id":"EMP-1","zone_id":"zone-main-gate"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleResetAPB_RejectsBadJSON(t *testing.T) {
	f := newFixture()
	rec := do(t, f.h.HandleResetAPB, http.MethodPost, "/reset", `nope`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestHandleResetAPB_DownstreamError(t *testing.T) {
	f := newFixture()
	f.pol.resetErr = status.Error(codes.Internal, "policy store down")
	rec := do(t, f.h.HandleResetAPB, http.MethodPost, "/reset", `{"employee_id":"E"}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", rec.Code)
	}
}

func TestHandleHealthz_ReflectsDownstreamState(t *testing.T) {
	// Health must report reality, not return 200 unconditionally. With the
	// gRPC connections unset in this fixture every downstream is unreachable,
	// so the correct answer is 503 - a gateway that claims healthy while its
	// dependencies are down would keep receiving traffic it cannot serve.
	f := newFixture()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := do(t, f.h.HandleHealthz, method, "/healthz", "", nil)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s /healthz = %d; want 503 when every downstream is unreachable",
				method, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewGatewayHandler_DefaultsLogger(t *testing.T) {
	f := newFixture()
	if f.h == nil {
		t.Fatal("NewGatewayHandler returned nil")
	}
	// Constructing with a nil logger must not panic on the first request.
	rec := do(t, f.h.HandleHealthz, http.MethodGet, "/healthz", "", nil)
	if rec.Code < 400 || rec.Code > 599 {
		t.Errorf("status = %d; want a valid HTTP status with a nil logger", rec.Code)
	}
}
