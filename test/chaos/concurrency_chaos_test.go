package chaos

import (
	"fmt"
	"sync"
	"testing"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
)

// ---------------------------------------------------------------------------
// Concurrency chaos. Run with -race for full value.
// ---------------------------------------------------------------------------

// Concurrent duplicate enrolment of the same identity must leave the store in a
// consistent state: a template must still be readable, never a torn record.
func TestChaos_ConcurrentDuplicateEnroll(t *testing.T) {
	const dim = "concurrency-duplicate-enroll"
	c := NewBioCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for round := 0; round < 8; round++ {
		t.Run("round", func(t *testing.T) {
			record(dim, "round-"+itoa(float64(round)))
			var wg sync.WaitGroup
			var mu sync.Mutex
			okCount := 0
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, cancel := ctxFor(t, 30*time.Second)
					defer cancel()
					_, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
						EmployeeId: "RACE", FullName: "Race", Position: genPos,
						ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500})
					if err == nil {
						mu.Lock()
						okCount++
						mu.Unlock()
					}
				}(i)
			}
			wg.Wait()
			observe(dim, fmt.Sprintf("round %d: %d/12 concurrent enrols succeeded", round, okCount))

			// INV-CORRECT: the store must remain readable and self-consistent.
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			got, err := c.Bio.GetTemplate(ctx, &biometricsv1.GetTemplateRequest{
				EmployeeId: "RACE", Position: genPos})
			if err != nil {
				t.Errorf("[%s] store unreadable after concurrent enrolment: %v", dim, err)
				return
			}
			if !got.Found {
				t.Errorf("[%s] store lost the template after concurrent enrolment", dim)
			}
			record(dim, "round-"+itoa(float64(round))+"/readback")
		})
	}
}

// Concurrent verification against a stable enrolled template.
func TestChaos_ConcurrentVerify(t *testing.T) {
	const dim = "concurrency-verify"
	c := enrolledCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for round := 0; round < 4; round++ {
		t.Run("round", func(t *testing.T) {
			record(dim, "round-"+itoa(float64(round)))
			var wg sync.WaitGroup
			var mu sync.Mutex
			matched, mismatched, errored := 0, 0, 0
			for i := 0; i < 24; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, cancel := ctxFor(t, 40*time.Second)
					defer cancel()
					r, err := c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
						EmployeeId: genEmp, Position: genPos,
						ProbeImageRawGray: img, Width: imgW, Height: imgH})
					mu.Lock()
					switch {
					case err != nil:
						errored++
					case r.IsMatch:
						matched++
					default:
						mismatched++
					}
					mu.Unlock()
				}(i)
			}
			wg.Wait()
			observe(dim, fmt.Sprintf("round %d: matched=%d mismatch=%d error=%d", round, matched, mismatched, errored))
			// INV-DETERMINISM: identical probes against an unchanged gallery
			// must not disagree with themselves under concurrency.
			if mismatched > 0 {
				t.Errorf("[%s] %d identical probes failed to match under concurrency", dim, mismatched)
			}
			record(dim, "round-"+itoa(float64(round))+"/aggregate")
		})
	}
}

// Concurrent APB evaluation for the same identity exercises the policy state
// machine under contention.
func TestChaos_ConcurrentPolicy(t *testing.T) {
	const dim = "concurrency-policy"
	c := NewPolicyCluster(t)

	for round := 0; round < 6; round++ {
		t.Run("round", func(t *testing.T) {
			record(dim, "round-"+itoa(float64(round)))
			var wg sync.WaitGroup
			var mu sync.Mutex
			bothGranted := 0
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, cancel := ctxFor(t, 30*time.Second)
					defer cancel()
					emp := fmt.Sprintf("CP-%d-%d", round, i)
					r1, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
						EmployeeId: emp, ZoneId: "zone-main-gate", DoorId: "d",
						Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
						BiometricVerified: true, BiometricScore: 90, TimestampUnix: time.Now().Unix()})
					if err != nil || !r1.IsGranted {
						return
					}
					r2, err2 := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
						EmployeeId: emp, ZoneId: "zone-main-gate", DoorId: "d",
						Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
						BiometricVerified: true, BiometricScore: 90, TimestampUnix: time.Now().Unix()})
					if err2 != nil {
						return
					}
					if r2.IsGranted {
						mu.Lock()
						bothGranted++
						mu.Unlock()
					}
				}(i)
			}
			wg.Wait()
			if bothGranted > 0 {
				t.Errorf("[%s] INV-NOBYPASS: %d concurrent double-entry pairs were both granted", dim, bothGranted)
			}
			record(dim, "round-"+itoa(float64(round))+"/aggregate")
		})
	}
}

// Concurrent turnstile scans racing against roster synchronisation.
func TestChaos_ConcurrentScanAndSync(t *testing.T) {
	const dim = "concurrency-edge"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for round := 0; round < 4; round++ {
		t.Run("round", func(t *testing.T) {
			record(dim, "round-"+itoa(float64(round)))
			var wg sync.WaitGroup
			var mu sync.Mutex
			completed := 0
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, cancel := ctxFor(t, 40*time.Second)
					defer cancel()
					_, err := c.Edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
						TurnstileId: "t", ZoneId: "zone-main-gate",
						Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
						EmployeeId:        fmt.Sprintf("SCAN-%d", i),
						ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
						ScanTimestampUnix: time.Now().Unix()})
					if err == nil {
						mu.Lock()
						completed++
						mu.Unlock()
					}
				}(i)
			}
			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, cancel := ctxFor(t, 40*time.Second)
					defer cancel()
					_, _ = c.Edge.SyncFacilityRoster(ctx, &edgegatewayv1.SyncFacilityRosterRequest{
						FacilityId: "f", Items: []*edgegatewayv1.SyncEmployeeItem{
							{EmployeeId: fmt.Sprintf("SYNC-%d", i), IsActive: true},
						}})
				}(i)
			}
			wg.Wait()
			observe(dim, fmt.Sprintf("round %d: %d/20 scans completed without error", round, completed))
			record(dim, "round-"+itoa(float64(round))+"/aggregate")
		})
	}
}

// Deep fan-out: many simultaneous requests must not deadlock or panic.
func TestChaos_DeepFanout(t *testing.T) {
	const dim = "deep-fanout"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	record(dim, "fanout-200")
	var wg sync.WaitGroup
	errCount := 0
	var mu sync.Mutex
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := ctxFor(t, 60*time.Second)
			defer cancel()
			var err error
			switch i % 3 {
			case 0:
				_, err = c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
					EmployeeId: fmt.Sprintf("FO-%d", i), FullName: "FO", Position: genPos,
					ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500})
			case 1:
				_, err = c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
					EmployeeId: fmt.Sprintf("FO-%d", i-1), Position: genPos,
					ProbeImageRawGray: img, Width: imgW, Height: imgH})
			case 2:
				_, err = c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
					EmployeeId: fmt.Sprintf("FO-%d", i-2), ZoneId: "zone-main-gate", DoorId: "d",
					Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
					BiometricVerified: true, BiometricScore: 90, TimestampUnix: time.Now().Unix()})
			}
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	observe(dim, fmt.Sprintf("200-way fanout completed, %d errors (expected: verify-before-enroll)", errCount))
}
