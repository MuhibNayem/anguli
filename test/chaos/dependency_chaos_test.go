package chaos

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	edgegatewayservice "finger-scanner/services/edge-gateway-service"
)

// ---------------------------------------------------------------------------
// Dependency failure chaos
// ---------------------------------------------------------------------------

// deadPolicyAddr returns an address with nothing listening on it.
func deadPolicyAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// Edge gateway pointed at a policy service that does not exist.
func TestChaos_PolicyUnavailable(t *testing.T) {
	const dim = "dependency-policy-down"
	dead := deadPolicyAddr(t)

	srv, ln := grpcServer(t)
	edgegatewayservice.RegisterServiceWithPolicy(srv,
		accesscontrolv1.NewAccessPolicyServiceClient(
			mustDial(t, dead)), nil)
	serve(t, srv, ln)
	conn := dial(t, ln.Addr().String())
	t.Cleanup(func() { conn.Close(); srv.Stop() })
	edge := edgegatewayv1.NewEdgeGatewayServiceClient(conn)

	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for i := 0; i < 10; i++ {
		t.Run("scan-without-policy", func(t *testing.T) {
			record(dim, "scan-without-policy-"+itoa(float64(i)))
			ctx, cancel := ctxFor(t, 20*time.Second)
			defer cancel()
			r, err := edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
				TurnstileId: "t", ZoneId: "zone-main-gate",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				EmployeeId:        fmt.Sprintf("DP-%d", i),
				ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
				ScanTimestampUnix: time.Now().Unix()})
			if err != nil {
				observe(dim, "scan errored cleanly: "+shortErr(err))
				return
			}
			observe(dim, "policy-down scan: granted="+boolStr(r.IsAccessGranted)+
				" relay="+itoa(float64(r.RelayStrikeDurationMs))+" offline="+boolStr(r.ProcessedOffline)+
				" reason="+r.Reason)
			// The identity was never enrolled, so this must never open the door
			// regardless of how the outage is handled.
			if r.IsAccessGranted {
				t.Errorf("[%s] INV-NOBYPASS: door opened for never-enrolled identity while policy was down", dim)
			}
		})
	}
}

// Edge gateway in standalone mode (policyClient == nil).
func TestChaos_EdgeStandalone(t *testing.T) {
	const dim = "dependency-standalone"
	srv, ln := grpcServer(t)
	edgegatewayservice.RegisterService(srv, nil)
	serve(t, srv, ln)
	conn := dial(t, ln.Addr().String())
	t.Cleanup(func() { conn.Close(); srv.Stop() })
	edge := edgegatewayv1.NewEdgeGatewayServiceClient(conn)

	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for i := 0; i < 10; i++ {
		t.Run("standalone-scan", func(t *testing.T) {
			record(dim, "standalone-scan-"+itoa(float64(i)))
			ctx, cancel := ctxFor(t, 20*time.Second)
			defer cancel()
			r, err := edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
				TurnstileId: "t", ZoneId: "zone-main-gate",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				EmployeeId:        fmt.Sprintf("SA-%d", i),
				ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
				ScanTimestampUnix: time.Now().Unix()})
			if err != nil {
				return
			}
			observe(dim, "standalone: granted="+boolStr(r.IsAccessGranted)+
				" offline="+boolStr(r.ProcessedOffline)+" relay="+itoa(float64(r.RelayStrikeDurationMs)))
			// Never-enrolled identity must never be granted, in either mode.
			if r.IsAccessGranted {
				t.Errorf("[%s] INV-NOBYPASS: standalone edge opened for never-enrolled identity", dim)
			}
		})
	}
}

// A biometric client pointed at a dead address must fail fast and cleanly.
func TestChaos_DeadDependency(t *testing.T) {
	const dim = "dependency-dead"
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for i := 0; i < 8; i++ {
		t.Run("dead-bio", func(t *testing.T) {
			record(dim, "dead-bio-"+itoa(float64(i)))
			conn := dial(t, deadPolicyAddr(t))
			defer conn.Close()
			cl := biometricsv1.NewBiometricsServiceClient(conn)
			ctx, cancel := ctxFor(t, 12*time.Second)
			defer cancel()
			t0 := time.Now()
			_, err := cl.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "DEAD", FullName: "D", Position: genPos,
				ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500})
			el := time.Since(t0)
			if err == nil {
				t.Errorf("[%s] call to a dead endpoint returned success", dim)
			}
			observe(dim, fmt.Sprintf("dead endpoint failed in %dms: %s", el.Milliseconds(), shortErr(err)))
		})
	}
}

// Cancelled and expired contexts must be honoured, not ignored.
func TestChaos_ContextCancellation(t *testing.T) {
	const dim = "dependency-context"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	record(dim, "already-cancelled-enroll")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
		EmployeeId: "CANCEL", FullName: "C", Position: genPos,
		ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500}); err == nil {
		t.Errorf("[%s] INV-CORRECT: request with a cancelled context succeeded", dim)
	}

	record(dim, "already-cancelled-policy")
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := c.Policy.EvaluateAccess(ctx2, &accesscontrolv1.EvaluateAccessRequest{
		EmployeeId: "CANCEL", ZoneId: "zone-main-gate", DoorId: "d",
		Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
		BiometricVerified: true, BiometricScore: 90, TimestampUnix: time.Now().Unix()}); err == nil {
		t.Errorf("[%s] INV-CORRECT: policy call with a cancelled context succeeded", dim)
	}

	record(dim, "microsecond-deadline")
	ctx3, cancel3 := context.WithTimeout(context.Background(), time.Microsecond)
	defer cancel3()
	time.Sleep(2 * time.Millisecond)
	if _, err := c.Bio.VerifyFingerprint(ctx3, &biometricsv1.VerifyFingerprintRequest{
		EmployeeId: "TIMEOUT", Position: genPos,
		ProbeImageRawGray: img, Width: imgW, Height: imgH}); err == nil {
		t.Errorf("[%s] INV-CORRECT: call with an expired deadline succeeded", dim)
	}
}

func mustDial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

// ---------------------------------------------------------------------------
// Resource chaos
// ---------------------------------------------------------------------------

// A large roster must remain responsive.
func TestChaos_LargeRoster(t *testing.T) {
	const dim = "resource-roster"
	srv, ln := grpcServer(t)
	edgegatewayservice.RegisterService(srv, nil)
	serve(t, srv, ln)
	conn := dial(t, ln.Addr().String())
	t.Cleanup(func() { conn.Close(); srv.Stop() })
	edge := edgegatewayv1.NewEdgeGatewayServiceClient(conn)

	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)
	ctx, cancel := ctxFor(t, 120*time.Second)
	defer cancel()

	for _, n := range []int{10, 50, 100, 250, 500} {
		items := make([]*edgegatewayv1.SyncEmployeeItem, n)
		for i := 0; i < n; i++ {
			items[i] = &edgegatewayv1.SyncEmployeeItem{
				EmployeeId: fmt.Sprintf("R-%d", i), IsActive: true}
		}
		t0 := time.Now()
		resp, err := edge.SyncFacilityRoster(ctx, &edgegatewayv1.SyncFacilityRosterRequest{
			FacilityId: "big", Items: items})
		el := time.Since(t0)
		record(dim, "roster-"+itoa(float64(n)))
		if err != nil {
			t.Errorf("[%s] roster of %d failed: %v", dim, n, err)
			continue
		}
		if int(resp.SyncedCount) != n {
			t.Errorf("[%s] roster of %d synced %d entries", dim, n, resp.SyncedCount)
		}
		observe(dim, fmt.Sprintf("roster %d synced in %dms", n, el.Milliseconds()))

		t0 = time.Now()
		if _, err := edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
			TurnstileId: "t", ZoneId: "zone-main-gate",
			Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
			EmployeeId:        "R-0",
			ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
			ScanTimestampUnix: time.Now().Unix()}); err != nil {
			t.Errorf("[%s] scan against roster of %d failed: %v", dim, n, err)
		}
		record(dim, "scan-with-roster-"+itoa(float64(n)))
		observe(dim, fmt.Sprintf("scan against roster %d took %dms", n, time.Since(t0).Milliseconds()))
	}
}

// Large images must be bounded, not unbounded in memory or time.
func TestChaos_LargeImages(t *testing.T) {
	const dim = "resource-large-image"
	c := NewBioCluster(t)

	for _, sz := range []int{400, 500, 600, 800} {
		sz := sz
		t.Run("size", func(t *testing.T) {
			record(dim, "size-"+itoa(float64(sz)))
			img := LoopPrint(sz, sz, float64(sz)*0.5, float64(sz)*0.5, 8.0, 3)
			ctx, cancel := ctxFor(t, 90*time.Second)
			defer cancel()
			t0 := time.Now()
			_, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "BIG-" + itoa(float64(sz)), FullName: "Big", Position: genPos,
				ImageRawGray: img, Width: uint32(sz), Height: uint32(sz), Dpi: 500})
			el := time.Since(t0)
			if err != nil {
				observe(dim, fmt.Sprintf("%dx%d rejected after %dms: %s", sz, sz, el.Milliseconds(), shortErr(err)))
				return
			}
			observe(dim, fmt.Sprintf("%dx%d enrolled in %dms", sz, sz, el.Milliseconds()))
			record(dim, "size-"+itoa(float64(sz))+"/done")
		})
	}
}

// Sustained load must not degrade into failure.
func TestChaos_SustainedLoad(t *testing.T) {
	const dim = "resource-sustained"
	c := enrolledCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	record(dim, "sustained-300")
	var wg sync.WaitGroup
	var mu sync.Mutex
	latencies := make([]time.Duration, 0, 300)
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := ctxFor(t, 90*time.Second)
			defer cancel()
			t0 := time.Now()
			_, _ = c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
				EmployeeId: genEmp, Position: genPos,
				ProbeImageRawGray: img, Width: imgW, Height: imgH})
			mu.Lock()
			latencies = append(latencies, time.Since(t0))
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	var total time.Duration
	var max time.Duration
	for _, d := range latencies {
		total += d
		if d > max {
			max = d
		}
	}
	avg := total / time.Duration(len(latencies))
	observe(dim, fmt.Sprintf("300 concurrent verifies: avg=%dms max=%dms", avg.Milliseconds(), max.Milliseconds()))
	if max > 30*time.Second {
		t.Errorf("[%s] INV-BOUNDED: worst-case latency %dms under load", dim, max.Milliseconds())
	}
	record(dim, "sustained-300/aggregate")
}
