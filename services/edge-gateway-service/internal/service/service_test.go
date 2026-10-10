package service_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

type mockPolicyClient struct {
	accesscontrolv1.AccessPolicyServiceClient
	granted  bool
	decision accesscontrolv1.AccessDecision
	reason   string
}

func (m *mockPolicyClient) EvaluateAccess(ctx context.Context, in *accesscontrolv1.EvaluateAccessRequest, opts ...grpc.CallOption) (*accesscontrolv1.EvaluateAccessResponse, error) {
	relay := int64(0)
	if m.granted {
		relay = 2500
	}
	return &accesscontrolv1.EvaluateAccessResponse{
		IsGranted:           m.granted,
		Decision:            m.decision,
		Reason:              m.reason,
		RelayOpenDurationMs: relay,
	}, nil
}

func TestEdgeService_M10_NoEmpIDOnFailedMatch(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()
	svc := service.NewEdgeService(cache, nil)

	// Enroll employee with empty cylinders (so match fails)
	_ = cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-FAILED-001",
		FullName:   "Test User",
		IsActive:   true,
		Cylinders:  nil,
	})

	// Probe
	rawPix := make([]byte, 120*120)
	for i := range rawPix {
		rawPix[i] = 200
	}

	res, err := svc.ProcessScan(ctx, "turnstile-01", "zone-main-gate", 1, "EMP-FAILED-001", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.IsAccessGranted {
		t.Errorf("expected access to be denied on biometric mismatch")
	}

	// M10: On failed match, matched employee ID MUST NOT be set
	if res.MatchedEmployeeID != "" {
		t.Errorf("expected MatchedEmployeeID to be empty on failed match, got %q", res.MatchedEmployeeID)
	}
}

func TestEdgeService_H5_FailOpenPrevention(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()

	// Mock policy client that DENIES access (e.g. APB violation)
	policyClient := &mockPolicyClient{
		granted:  false,
		decision: accesscontrolv1.AccessDecision_ACCESS_DECISION_DENIED_ANTI_PASSBACK,
		reason:   "Anti-passback violation at turnstile",
	}

	svc := service.NewEdgeServiceWithPolicy(cache, policyClient, nil)

	// Create valid minutiae template
	pts := []minutiae.Minutia{
		{X: 30, Y: 30, Angle: 0.5, Type: minutiae.TypeEnding, Quality: 80},
		{X: 50, Y: 50, Angle: 1.0, Type: minutiae.TypeBifurcation, Quality: 80},
		{X: 70, Y: 70, Angle: 1.5, Type: minutiae.TypeEnding, Quality: 80},
	}
	tmpl := mcc.BuildTemplate("EMP-APB-001", pts)

	_ = cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-APB-001",
		FullName:   "APB Test",
		IsActive:   true,
		Cylinders:  tmpl.Cylinders,
	})

	// Synthetic print matching points
	rawPix := make([]byte, 120*120)
	for i := range rawPix {
		rawPix[i] = 128
	}

	res, err := svc.ProcessScan(ctx, "turnstile-01", "zone-main-gate", 1, "EMP-APB-001", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Even if biometrics match, if policy denies, relay MUST NOT be struck (Fix H5)
	if res.IsAccessGranted {
		t.Errorf("expected access denied when central policy denies")
	}
	if res.RelayStrikeDurationMs != 0 {
		t.Errorf("relay strike duration must be 0 when policy denies, got %d", res.RelayStrikeDurationMs)
	}
}

func TestEdgeService_H7_H8_DurableWALPersistence(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	walPath := filepath.Join(tmpDir, "test_edge.wal")

	// 1. Initialize edge cache with explicit WAL file
	cache1 := memory.NewDurableEdgeCache(walPath)
	event1 := &domain.OfflineAuditLog{
		EventID:       "evt-001",
		TurnstileID:   "turnstile-01",
		EmployeeID:    "EMP-100",
		AccessGranted: true,
		Decision:      "Access granted",
		TimestampUnix: 1700000000,
	}
	if err := cache1.AppendOfflineEvent(ctx, event1); err != nil {
		t.Fatalf("failed to append offline event: %v", err)
	}

	if cache1.GetOfflineEventCount(ctx) != 1 {
		t.Errorf("expected 1 event in cache1, got %d", cache1.GetOfflineEventCount(ctx))
	}

	// Verify WAL file exists and contains data on disk
	fi, err := os.Stat(walPath)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("expected non-empty WAL file on disk, err: %v", err)
	}

	// 2. Simulate process restart by creating a new cache pointing to the same WAL file
	cache2 := memory.NewDurableEdgeCache(walPath)
	if cache2.GetOfflineEventCount(ctx) != 1 {
		t.Errorf("expected 1 recovered event in cache2 after restart, got %d", cache2.GetOfflineEventCount(ctx))
	}

	// 3. Drain events and verify WAL file is truncated
	drained, err := cache2.DrainOfflineEvents(ctx)
	if err != nil || len(drained) != 1 {
		t.Fatalf("failed to drain events: %v, count: %d", err, len(drained))
	}

	fiDrained, _ := os.Stat(walPath)
	if fiDrained.Size() != 0 {
		t.Errorf("expected WAL file to be truncated to 0 bytes after drain, got %d", fiDrained.Size())
	}
}

type mockFailingPolicyClient struct {
	accesscontrolv1.AccessPolicyServiceClient
}

func (m *mockFailingPolicyClient) EvaluateAccess(ctx context.Context, in *accesscontrolv1.EvaluateAccessRequest, opts ...grpc.CallOption) (*accesscontrolv1.EvaluateAccessResponse, error) {
	return nil, status.Error(codes.Unavailable, "connection refused: central service down")
}

func (m *mockFailingPolicyClient) GetPolicy(ctx context.Context, in *accesscontrolv1.GetPolicyRequest, opts ...grpc.CallOption) (*accesscontrolv1.GetPolicyResponse, error) {
	return nil, status.Error(codes.Unavailable, "connection refused")
}

func generateTestPrint(w, h int) ([]byte, []mcc.Cylinder) {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 200
	}
	for r := 20; r < h-20; r += 6 {
		for c := 20; c < w-20; c++ {
			if c%28 == 0 {
				continue
			}
			if (r+c)%45 == 0 && r+3 < h-20 {
				pix[(r+2)*w+c] = 40
			}
			pix[r*w+c] = 40
			if r+1 < h {
				pix[(r+1)*w+c] = 50
			}
		}
	}
	img, _ := image.NewGrayImage(w, h, pix)
	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(15)
	skel := image.ZhangSuenThinning(bin, w, h)
	ori := norm.OrientationField(16)
	pts := minutiae.NewExtractor().Extract(skel, w, h, ori, 16)
	tmpl := mcc.BuildTemplate("test", pts)
	return pix, tmpl.Cylinders
}

func TestEdgeService_OfflineFogNodeSurvivability(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()

	// Seed cached zone policy
	_ = cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
		ZoneID:                "zone-main-gate",
		AllowedRole:           "EMPLOYEE",
		RequireBiometrics:     true,
		MinBiometricScore:     60.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	})

	// Central policy is completely DOWN
	policyClient := &mockFailingPolicyClient{}
	svc := service.NewEdgeServiceWithPolicy(cache, policyClient, nil)

	rawPix, cyls := generateTestPrint(120, 120)

	_ = cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-OFFLINE-001",
		FullName:   "Offline Worker",
		Role:       "EMPLOYEE",
		IsActive:   true,
		Cylinders:  cyls,
	})

	// First scan (Entry): Must succeed offline, strike relay, and record offline pass
	res1, err := svc.ProcessScan(ctx, "turnstile-01", "zone-main-gate", 1, "EMP-OFFLINE-001", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("unexpected error during offline scan: %v", err)
	}

	if !res1.IsAccessGranted {
		t.Fatalf("expected 100%% offline survivability grant, got reason: %s", res1.Reason)
	}
	if res1.RelayStrikeDurationMs != 2500 {
		t.Errorf("expected 2500ms solenoid relay strike, got %d", res1.RelayStrikeDurationMs)
	}
	if !res1.ProcessedOffline {
		t.Errorf("expected ProcessedOffline=true")
	}

	// Second immediate scan (Duplicate Entry): Must be rejected by local APB even while offline!
	res2, err := svc.ProcessScan(ctx, "turnstile-01", "zone-main-gate", 1, "EMP-OFFLINE-001", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("unexpected error during second offline scan: %v", err)
	}

	if res2.IsAccessGranted {
		t.Fatalf("expected anti-passback rejection on duplicate entry, but access was granted")
	}
	if res2.RelayStrikeDurationMs != 0 {
		t.Errorf("expected relay strike to be 0ms on APB denial, got %d", res2.RelayStrikeDurationMs)
	}
	if res2.Decision != 3 {
		t.Errorf("expected Decision=3 (DENIED_ANTI_PASSBACK), got %d", res2.Decision)
	}
}

func TestEdgeService_OfflineRoleRejection(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()

	// High security zone requiring SECURITY_ADMIN
	_ = cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
		ZoneID:                "zone-server-vault",
		AllowedRole:           "SECURITY_ADMIN",
		RequireBiometrics:     true,
		MinBiometricScore:     60.0,
		EnforceAntiPassback:   false,
		AntiPassbackWindowSec: 0,
	})

	policyClient := &mockFailingPolicyClient{}
	svc := service.NewEdgeServiceWithPolicy(cache, policyClient, nil)

	rawPix, cyls := generateTestPrint(120, 120)

	_ = cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-BASIC-001",
		FullName:   "Standard Employee",
		Role:       "EMPLOYEE", // Insufficient clearance
		IsActive:   true,
		Cylinders:  cyls,
	})

	res, err := svc.ProcessScan(ctx, "turnstile-vault", "zone-server-vault", 1, "EMP-BASIC-001", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.IsAccessGranted {
		t.Fatalf("expected role denial for standard employee in SECURITY_ADMIN zone")
	}
	if res.RelayStrikeDurationMs != 0 {
		t.Errorf("expected 0ms relay on role denial, got %d", res.RelayStrikeDurationMs)
	}
	if res.Decision != 2 {
		t.Errorf("expected Decision=2 (DENIED_INVALID_ZONE), got %d", res.Decision)
	}
}

func TestEdgeService_DynamicStatus(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()
	failingClient := &mockFailingPolicyClient{}

	svcOffline := service.NewEdgeServiceWithPolicy(cache, failingClient, nil)
	stOffline, err := svcOffline.GetStatus(ctx, "turnstile-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stOffline.IsOnline {
		t.Errorf("expected IsOnline=false when policy service is unreachable")
	}
}
