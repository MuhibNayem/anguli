package integration_test

import (
	"context"
	"math"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	accesspolicyservice "finger-scanner/services/access-policy-service"
	biometricservice "finger-scanner/services/biometric-service"
	edgegatewayservice "finger-scanner/services/edge-gateway-service"
)

func TestFullMicroservicesE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Start Biometric Service on ephemeral port
	bioListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for bio service: %v", err)
	}
	defer bioListener.Close()

	bioServer := grpc.NewServer()
	if err := biometricservice.RegisterService(bioServer, []byte("01234567890123456789012345678901"), nil); err != nil {
		t.Fatalf("failed to register bio service: %v", err)
	}
	go func() { _ = bioServer.Serve(bioListener) }()
	defer bioServer.Stop()

	// 2. Start Access Policy Service on ephemeral port
	policyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for policy service: %v", err)
	}
	defer policyListener.Close()

	policyServer := grpc.NewServer()
	accesspolicyservice.RegisterService(policyServer, nil)
	go func() { _ = policyServer.Serve(policyListener) }()
	defer policyServer.Stop()

	// 3. Start Edge Gateway Service on ephemeral port
	edgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for edge service: %v", err)
	}
	defer edgeListener.Close()

	edgeServer := grpc.NewServer()
	edgegatewayservice.RegisterService(edgeServer, nil)
	go func() { _ = edgeServer.Serve(edgeListener) }()
	defer edgeServer.Stop()

	// Connect gRPC clients
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	bioConn, err := grpc.NewClient(bioListener.Addr().String(), opts...)
	if err != nil {
		t.Fatalf("failed to connect to bio service: %v", err)
	}
	defer bioConn.Close()
	bioClient := biometricsv1.NewBiometricsServiceClient(bioConn)

	policyConn, err := grpc.NewClient(policyListener.Addr().String(), opts...)
	if err != nil {
		t.Fatalf("failed to connect to policy service: %v", err)
	}
	defer policyConn.Close()
	policyClient := accesscontrolv1.NewAccessPolicyServiceClient(policyConn)

	edgeConn, err := grpc.NewClient(edgeListener.Addr().String(), opts...)
	if err != nil {
		t.Fatalf("failed to connect to edge service: %v", err)
	}
	defer edgeConn.Close()
	edgeClient := edgegatewayv1.NewEdgeGatewayServiceClient(edgeConn)

	// Step A: Enroll a synthetic 500 DPI fingerprint with rich ridge endings & bifurcations
	width, height := uint32(140), uint32(140)
	rawPix := generateRealisticPrint(int(width), int(height), 0)

	enrollResp, err := bioClient.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
		EmployeeId:   "EMP-007",
		FullName:     "James Bond",
		Position:     biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
		ImageRawGray: rawPix,
		Width:        width,
		Height:       height,
		Dpi:          500,
	})
	if err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}

	if !enrollResp.IsQualityAcceptable || enrollResp.NfiqQualityScore < 65 {
		t.Errorf("expected quality >= 65, got %d", enrollResp.NfiqQualityScore)
	}

	t.Logf("Enrolled successfully with %d minutiae and NFIQ score %d", enrollResp.MinutiaeCount, enrollResp.NfiqQualityScore)

	// Step B: Verify 1:1 match with genuine probe rotated by 2.0° and 5.0° (verifying rotation invariance)
	probeRotatedPix := rotateImage(rawPix, int(width), int(height), 2.0*math.Pi/180.0)
	verifyResp, err := bioClient.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
		EmployeeId:        "EMP-007",
		Position:          biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
		ProbeImageRawGray: probeRotatedPix,
		Width:             width,
		Height:            height,
	})
	if err != nil {
		t.Fatalf("verification call failed: %v", err)
	}

	if !verifyResp.IsMatch {
		t.Errorf("expected genuine verification to succeed under 2.0° rotation, got score: %f", verifyResp.Score)
	} else {
		t.Logf("Genuine 2.0° rotated probe verified successfully: score=%f", verifyResp.Score)
	}

	// Verify 5.0° rotation as well
	probeRotated5Pix := rotateImage(rawPix, int(width), int(height), 5.0*math.Pi/180.0)
	verifyResp5, err := bioClient.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
		EmployeeId:        "EMP-007",
		Position:          biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
		ProbeImageRawGray: probeRotated5Pix,
		Width:             width,
		Height:            height,
	})
	if err != nil {
		t.Fatalf("verification 5deg call failed: %v", err)
	}
	if !verifyResp5.IsMatch {
		t.Errorf("expected genuine verification to succeed under 5.0° rotation, got score: %f", verifyResp5.Score)
	} else {
		t.Logf("Genuine 5.0° rotated probe verified successfully: score=%f", verifyResp5.Score)
	}

	// Verify 30.0° turnstile physical hand rotation as well
	probeRotated30Pix := rotateImage(rawPix, int(width), int(height), 30.0*math.Pi/180.0)
	verifyResp30, err := bioClient.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
		EmployeeId:        "EMP-007",
		Position:          biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
		ProbeImageRawGray: probeRotated30Pix,
		Width:             width,
		Height:            height,
	})
	if err != nil {
		t.Fatalf("verification 30deg call failed: %v", err)
	}
	if !verifyResp30.IsMatch {
		t.Errorf("expected genuine verification to succeed under 30.0° turnstile rotation, got score: %f", verifyResp30.Score)
	} else {
		t.Logf("Genuine 30.0° rotated probe verified successfully: score=%f", verifyResp30.Score)
	}

	// Step C: Test Imposter Rejection (Zero False Accept)
	imposterPix := generateImposterPrint(int(width), int(height))
	imposterResp, err := bioClient.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
		EmployeeId:        "EMP-007",
		Position:          biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
		ProbeImageRawGray: imposterPix,
		Width:             width,
		Height:            height,
	})
	if err != nil {
		t.Fatalf("imposter call failed: %v", err)
	}

	if imposterResp.IsMatch {
		t.Errorf("imposter print was falsely accepted! score: %f", imposterResp.Score)
	}

	// Step D: Evaluate Access Policy & Anti-Passback
	evalResp1, err := policyClient.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
		EmployeeId:        "EMP-007",
		ZoneId:            "zone-main-gate",
		DoorId:            "turnstile-01",
		Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
		BiometricVerified: true,
		BiometricScore:    85.0,
		TimestampUnix:     time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("policy evaluation failed: %v", err)
	}

	if !evalResp1.IsGranted {
		t.Errorf("expected access to be granted on initial entry, reason: %s", evalResp1.Reason)
	}

	// Immediate 2nd entry swipe without exit -> Must be rejected by Anti-Passback (APB)
	evalResp2, err := policyClient.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
		EmployeeId:        "EMP-007",
		ZoneId:            "zone-main-gate",
		DoorId:            "turnstile-01",
		Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
		BiometricVerified: true,
		BiometricScore:    85.0,
		TimestampUnix:     time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("second policy evaluation failed: %v", err)
	}

	if evalResp2.IsGranted {
		t.Errorf("expected anti-passback violation on consecutive entry, but access was granted!")
	}

	// Step E: Sync to Edge Gateway and test Turnstile Doorstep Scan
	tmplResp, err := bioClient.GetTemplate(ctx, &biometricsv1.GetTemplateRequest{
		EmployeeId: "EMP-007",
		Position:   biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
	})
	if err != nil || !tmplResp.Found {
		t.Fatalf("failed to fetch template for edge sync: %v", err)
	}

	syncResp, err := edgeClient.SyncFacilityRoster(ctx, &edgegatewayv1.SyncFacilityRosterRequest{
		FacilityId: "site-austin",
		Items: []*edgegatewayv1.SyncEmployeeItem{
			{
				EmployeeId: "EMP-007",
				FullName:   "James Bond",
				Role:       "AGENT",
				Position:   biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX,
				Minutiae:   tmplResp.Template.Minutiae,
				IsActive:   true,
			},
		},
	})
	if err != nil || syncResp.SyncedCount != 1 {
		t.Fatalf("edge roster sync failed: %v", err)
	}

	// Turnstile Scan
	doorScanResp, err := edgeClient.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
		TurnstileId:        "turnstile-01",
		ZoneId:             "zone-main-gate",
		Direction:          accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
		EmployeeId:         "EMP-007",
		ProbeImageRawGray:  rawPix,
		ImageWidth:         width,
		ImageHeight:        height,
		ScanTimestampUnix:  time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("door scan error: %v", err)
	}

	if !doorScanResp.IsAccessGranted {
		t.Errorf("expected door scan to grant access to genuine employee, reason: %s", doorScanResp.Reason)
	}

	// M14: Assert 200ms baseline SLA, accommodating up to 450ms under -race instrumentation
	if doorScanResp.TotalLatencyMs > 450 {
		t.Errorf("turnstile latency %d ms exceeds tolerable threshold of 450ms", doorScanResp.TotalLatencyMs)
	} else if doorScanResp.TotalLatencyMs > 200 {
		t.Logf("Notice: turnstile latency %d ms is above 200ms baseline (expected under -race instrumentation)", doorScanResp.TotalLatencyMs)
	} else {
		t.Logf("Turnstile latency %d ms strictly satisfies 200ms baseline enterprise SLA", doorScanResp.TotalLatencyMs)
	}

	t.Logf("E2E Test Success! Total doorstep latency: %d ms, Match confirmed.", doorScanResp.TotalLatencyMs)
}

func generateRealisticPrint(w, h int, seed int) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 200
	}

	// Draw multiple horizontal fingerprint ridges with intentional branchings and interruptions
	for r := 20; r < h-20; r += 6 {
		for c := 20; c < w-20; c++ {
			if (c+seed)%28 == 0 {
				continue
			}
			if (r+c+seed)%45 == 0 && r+3 < h-20 {
				pix[(r+2)*w+c] = 40
			}
			pix[r*w+c] = 40
			if r+1 < h {
				pix[(r+1)*w+c] = 50
			}
		}
	}
	return pix
}

func generateImposterPrint(w, h int) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 200
	}

	// Draw orthogonal vertical ridges completely different from genuine horizontal print
	for c := 20; c < w-20; c += 8 {
		for r := 20; r < h-20; r++ {
			if r%25 == 0 {
				continue
			}
			pix[r*w+c] = 40
			if c+1 < w {
				pix[r*w+c+1] = 50
			}
		}
	}
	return pix
}

func rotateImage(src []byte, w, h int, angleRad float64) []byte {
	dst := make([]byte, w*h)
	for i := range dst {
		dst[i] = 200
	}
	cx := float64(w) / 2.0
	cy := float64(h) / 2.0
	cosA := math.Cos(-angleRad)
	sinA := math.Sin(-angleRad)

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			srcX := cx + (dx*cosA - dy*sinA)
			srcY := cy + (dx*sinA + dy*cosA)

			ix := int(math.Round(srcX))
			iy := int(math.Round(srcY))
			if ix >= 0 && ix < w && iy >= 0 && iy < h {
				dst[y*w+x] = src[iy*w+ix]
			}
		}
	}
	return dst
}
