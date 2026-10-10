package chaos

import (
	"testing"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
)

// ---------------------------------------------------------------------------
// Lookup abuse against an EMPTY store.
//
// The store must contain no template for these identities, so any "found" or
// "matched" result is a genuine invariant violation rather than an artefact of
// the test having enrolled the same identifier moments earlier.
// ---------------------------------------------------------------------------

func TestChaos_LookupAbuse(t *testing.T) {
	const dim = "lookup-abuse"
	c := NewBioCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for _, s := range hostileStrings() {
		t.Run(s.name+"/verify", func(t *testing.T) {
			t.Parallel()
			record(dim, s.name+"/verify")
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
				EmployeeId: s.val, Position: genPos,
				ProbeImageRawGray: img, Width: imgW, Height: imgH})
			if err == nil && r.IsMatch {
				t.Errorf("[%s] INV-NOBYPASS: unregistered identity %q matched, score %.2f", dim, s.name, r.Score)
			}
		})
		t.Run(s.name+"/gettemplate", func(t *testing.T) {
			t.Parallel()
			record(dim, s.name+"/gettemplate")
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Bio.GetTemplate(ctx, &biometricsv1.GetTemplateRequest{
				EmployeeId: s.val, Position: genPos})
			if err == nil && r.Found {
				t.Errorf("[%s] INV-NOSECRET: unregistered identity %q returned a template", dim, s.name)
			}
		})
	}

	// Wrong finger position against a store that has exactly one template.
	ctx, cancel := ctxFor(t, 20*time.Second)
	defer cancel()
	if _, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
		EmployeeId: "POS-OWNER", FullName: "Owner", Position: genPos,
		ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500}); err != nil {
		t.Fatalf("seed enroll: %v", err)
	}
	for i := 0; i < 12; i++ {
		t.Run("wrong-position", func(t *testing.T) {
			record(dim, "wrong-position-"+itoa(float64(i)))
			cx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Bio.VerifyFingerprint(cx, &biometricsv1.VerifyFingerprintRequest{
				EmployeeId: "POS-OWNER", Position: biometricsv1.FingerPosition(i % 12),
				ProbeImageRawGray: img, Width: imgW, Height: imgH})
			// Only the enrolled position may match.
			if err == nil && r.IsMatch && i%12 != int(genPos) {
				t.Errorf("[%s] INV-NOBYPASS: matched on unregistered finger position %d, score %.2f",
					dim, i%12, r.Score)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Enrolment abuse: hostile identifiers written into the store.
//
// Not asserted as a failure - the system is permitted to store unusual ids -
// but tracked, because NUL bytes and control characters in a storage key are a
// known source of downstream problems (logging, export, SQL, filesystem).
// ---------------------------------------------------------------------------

func TestChaos_EnrollAbuse(t *testing.T) {
	const dim = "enroll-abuse"
	c := NewBioCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for _, s := range hostileStrings() {
		t.Run(s.name, func(t *testing.T) {
			record(dim, s.name)
			ctx, cancel := ctxFor(t, 20*time.Second)
			defer cancel()
			r, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: s.val, FullName: s.val, Position: genPos,
				ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500})
			if err != nil {
				observe(dim, s.name+" rejected: "+shortErr(err))
				return
			}
			control := containsControl(s.val)
			observe(dim, s.name+" ACCEPTED (control-chars="+boolStr(control)+") minutiae="+itoa(float64(r.MinutiaeCount)))
			if control {
				observe(dim, "CONTROL-CHARACTER ID ACCEPTED: "+s.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Policy / edge abuse matrix
// ---------------------------------------------------------------------------

func TestChaos_PolicyEdgeAbuse(t *testing.T) {
	const dim = "policy-edge-abuse"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	zones := []string{
		"", " ", "\t", "zone-main-gate", "zone-factory-floor", "zone-datacenter",
		"zone-unknown", "ZONE-MAIN-GATE", "zone_main_gate", "../../etc/passwd",
		"\x00", "zone-emoji-🚪", "0", "-1", "null", longString(512),
		"\x00\x00zone", "zone\x00main", strings_Repeat("A", 2048),
	}
	strs := hostileStrings()

	for _, z := range zones {
		z := z
		t.Run("policy-zone", func(t *testing.T) {
			t.Parallel()
			record(dim, "policy-zone-"+zoneName(z))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId: "PE-" + zoneName(z), ZoneId: z, DoorId: "d",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				BiometricVerified: true, BiometricScore: 100, TimestampUnix: time.Now().Unix()})
			if err != nil {
				observe(dim, "policy zone="+zoneName(z)+" rejected: "+shortErr(err))
				return
			}
			observe(dim, "policy zone="+zoneName(z)+" granted="+boolStr(r.IsGranted))
		})
		t.Run("edge-zone", func(t *testing.T) {
			t.Parallel()
			record(dim, "edge-zone-"+zoneName(z))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
				TurnstileId: "t", ZoneId: z,
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				EmployeeId:        "PE-" + zoneName(z),
				ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
				ScanTimestampUnix: time.Now().Unix()})
			if err != nil {
				observe(dim, "edge zone="+zoneName(z)+" rejected: "+shortErr(err))
				return
			}
			observe(dim, "edge zone="+zoneName(z)+" granted="+boolStr(r.IsAccessGranted))
		})
	}

	for _, s := range strs {
		t.Run("edge-"+s.name, func(t *testing.T) {
			t.Parallel()
			record(dim, "edge-"+s.name)
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
				TurnstileId: s.val, ZoneId: "zone-main-gate",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				EmployeeId:        s.val,
				ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
				ScanTimestampUnix: time.Now().Unix()})
			if err != nil {
				return
			}
			// A never-enrolled identity must never be granted, whatever the
			// turnstile id looks like.
			if r.IsAccessGranted {
				t.Errorf("[%s] INV-NOBYPASS: edge granted for never-enrolled identity %q", dim, s.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Enum / numeric boundary chaos
// ---------------------------------------------------------------------------

func TestChaos_EnumBoundaries(t *testing.T) {
	const dim = "enum-boundaries"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	positions := []biometricsv1.FingerPosition{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 99, 100, 255, 1000, 65535, 2147483647}
	for _, p := range positions {
		p := p
		t.Run("fingerpos", func(t *testing.T) {
			t.Parallel()
			record(dim, "fingerpos-"+itoa(float64(p)))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			_, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "FP-" + itoa(float64(p)), FullName: "FP", Position: p,
				ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500})
			handleChaosResult(t, dim, "fingerpos", err)
		})
	}

	directions := []accesscontrolv1.DoorDirection{0, 1, 2, 3, 4, 99, 255, 1000, 65535, 2147483647}
	for _, d := range directions {
		d := d
		t.Run("direction", func(t *testing.T) {
			t.Parallel()
			record(dim, "direction-"+itoa(float64(d)))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId: "DIR-" + itoa(float64(d)), ZoneId: "zone-main-gate", DoorId: "d",
				Direction: d, BiometricVerified: true, BiometricScore: 90,
				TimestampUnix: time.Now().Unix()})
			handleChaosResult(t, dim, "direction", err)
			if err == nil {
				observe(dim, "direction "+itoa(float64(d))+" -> granted="+boolStr(r.IsGranted))
			}
		})
	}

	dpis := []uint32{0, 1, 72, 200, 300, 500, 501, 600, 1000, 1200, 2000, 100000, 4294967295}
	for _, dpi := range dpis {
		dpi := dpi
		t.Run("dpi", func(t *testing.T) {
			t.Parallel()
			record(dim, "dpi-"+itoa(float64(dpi)))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			_, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "DPI-" + itoa(float64(dpi)), FullName: "DPI", Position: genPos,
				ImageRawGray: img, Width: imgW, Height: imgH, Dpi: dpi})
			handleChaosResult(t, dim, "dpi", err)
		})
	}

	scores := []float64{0, 0.001, 1, 29.9, 30, 59.9, 59.99, 60, 60.01, 69.9, 70, 70.01, 99.9, 100, 1000, 1e9, -1, -1000}
	for _, s := range scores {
		s := s
		t.Run("score", func(t *testing.T) {
			t.Parallel()
			record(dim, "score-"+itoa(s))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId: "SC-" + itoa(s), ZoneId: "zone-main-gate", DoorId: "d",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				BiometricVerified: true, BiometricScore: s, TimestampUnix: time.Now().Unix()})
			handleChaosResult(t, dim, "score", err)
			if err == nil {
				observe(dim, "bio score "+itoa(s)+" -> granted="+boolStr(r.IsGranted))
			}
		})
	}

	timestamps := []int64{0, 1, -1, -1 << 40, 1 << 40, 1<<62 - 1}
	for _, ts := range timestamps {
		ts := ts
		t.Run("timestamp", func(t *testing.T) {
			t.Parallel()
			record(dim, "timestamp-"+itoa(float64(ts)))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			_, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId: "TS", ZoneId: "zone-main-gate", DoorId: "d",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				BiometricVerified: true, BiometricScore: 90, TimestampUnix: ts})
			handleChaosResult(t, dim, "timestamp", err)
		})
	}
}

// handleChaosResult records the outcome without failing: the system is allowed
// to accept, reject, or error, as long as it does not panic or bypass.
func handleChaosResult(t *testing.T, dim, name string, err error) {
	t.Helper()
	if err != nil {
		observe(dim, name+" rejected: "+shortErr(err))
		return
	}
	observe(dim, name+" accepted")
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func strings_Repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func zoneName(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "empty"
	}
	return s
}
