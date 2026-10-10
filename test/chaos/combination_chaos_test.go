package chaos

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
)

// ---------------------------------------------------------------------------
// Combined degradation chaos: the cross product of realistic capture faults.
//
// Real fingers are rarely either clean or singly-defective. This dimension
// composes blur, contrast loss, noise, erosion, partial area and rotation into
// combinations and checks the security invariant on every one of them.
// ---------------------------------------------------------------------------

type defect struct {
	name  string
	apply func([]byte) []byte
}

func defectOps(seed int64) []defect {
	return []defect{
		{"none", func(x []byte) []byte { return x }},
		{"blur0.8", func(x []byte) []byte { return GaussianBlur(x, imgW, imgH, 0.8) }},
		{"blur1.5", func(x []byte) []byte { return GaussianBlur(x, imgW, imgH, 1.5) }},
		{"blur2.2", func(x []byte) []byte { return GaussianBlur(x, imgW, imgH, 2.2) }},
		{"oily0.6", func(x []byte) []byte { return Oily(x, imgW, imgH, 1.0, 0.6) }},
		{"oily0.3", func(x []byte) []byte { return Oily(x, imgW, imgH, 1.0, 0.3) }},
		{"noise15", func(x []byte) []byte { return GaussianNoise(x, 15, seed) }},
		{"noise35", func(x []byte) []byte { return GaussianNoise(x, 35, seed) }},
		{"dry0.4", func(x []byte) []byte { return Dry(x, 110, 0.4, seed) }},
		{"dry0.7", func(x []byte) []byte { return Dry(x, 110, 0.7, seed) }},
		{"partial0.6", func(x []byte) []byte { return Partial(x, imgW, imgH, 0.6) }},
		{"partial0.35", func(x []byte) []byte { return Partial(x, imgW, imgH, 0.35) }},
		{"rot3", func(x []byte) []byte { return Rotate(x, imgW, imgH, 3) }},
		{"rot12", func(x []byte) []byte { return Rotate(x, imgW, imgH, 12) }},
		{"shift5", func(x []byte) []byte { return Shift(x, imgW, imgH, 5, 5) }},
		{"wet", func(x []byte) []byte { return Wet(x, imgW, imgH, 1.0, 95, 80, 34) }},
	}
}

func TestChaos_CombinedDegradation(t *testing.T) {
	const dim = "combined-degradation"
	c := enrolledCluster(t)
	gen := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)
	imp := LoopCorpus(imgW, imgH, 1)[0]
	ops := defectOps(21)

	// Full pairwise cross product of the defect set.
	for i, a := range ops {
		for j, b := range ops {
			if j < i {
				continue
			}
			name := a.name + "+" + b.name
			t.Run(name, func(t *testing.T) {
				record(dim, name+"/genuine")
				record(dim, name+"/imposter")

				degraded := func(src []byte) []byte { return b.apply(a.apply(src)) }

				gr := verifyProbe(t, c, genEmp, degraded(gen), imgW, imgH)
				if gr.err != nil {
					t.Errorf("[%s/%s] genuine probe errored: %v", dim, name, gr.err)
				} else {
					observe(dim, name+": genuine="+itoa(gr.score)+" match="+boolStr(gr.match))
				}
				ir := verifyProbe(t, c, genEmp, degraded(imp), imgW, imgH)
				assertNoFalseAccept(t, dim, name+"/imposter", ir)
			})
		}
	}

	// Randomised triples, deterministic per seed so failures reproduce.
	rng := rand.New(rand.NewSource(20261009))
	for n := 0; n < 120; n++ {
		a := ops[rng.Intn(len(ops))]
		b := ops[rng.Intn(len(ops))]
		cc := ops[rng.Intn(len(ops))]
		name := fmt.Sprintf("triple-%03d-%s-%s-%s", n, a.name, b.name, cc.name)
		t.Run(name, func(t *testing.T) {
			record(dim, name+"/genuine")
			record(dim, name+"/imposter")
			degraded := func(src []byte) []byte { return cc.apply(b.apply(a.apply(src))) }

			gr := verifyProbe(t, c, genEmp, degraded(gen), imgW, imgH)
			if gr.err != nil {
				t.Errorf("[%s/%s] genuine probe errored: %v", dim, name, gr.err)
			}
			ir := verifyProbe(t, c, genEmp, degraded(imp), imgW, imgH)
			assertNoFalseAccept(t, dim, name+"/imposter", ir)
		})
	}
}

// ---------------------------------------------------------------------------
// Identification (1:N) chaos: a probe must not resolve to the wrong identity.
// ---------------------------------------------------------------------------

func TestChaos_IdentificationCohort(t *testing.T) {
	const dim = "identification-cohort"
	c := NewBioCluster(t)
	ctx, cancel := ctxFor(t, 180*time.Second)
	defer cancel()

	corpus := LoopCorpus(imgW, imgH, 12)
	ids := make([]string, len(corpus))
	for i, img := range corpus {
		id := fmt.Sprintf("ID-%02d", i)
		ids[i] = id
		if _, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
			EmployeeId: id, FullName: id, Position: genPos,
			ImageRawGray: img, Width: imgW, Height: imgH, Dpi: 500}); err != nil {
			t.Fatalf("enrol %s: %v", id, err)
		}
		record(dim, "enroll-"+id)
	}

	// Every probe must either be rejected or resolve to its OWN enrolment.
	probe := func(label string, img []byte, wantID string) {
		t.Run(label, func(t *testing.T) {
			record(dim, "probe-"+label)
			cx, cancel := ctxFor(t, 40*time.Second)
			defer cancel()
			r, err := c.Bio.IdentifyFingerprint(cx, &biometricsv1.IdentifyFingerprintRequest{
				ProbeImageRawGray: img, Width: imgW, Height: imgH, TopK: 5})
			if err != nil {
				// A quality-gate rejection is a CORRECT outcome for a stranger,
				// not a test failure.
				if isQualityRejection(err) {
					record(dim, "probe-"+label+"/quality-rejected")
					observe(dim, label+": rejected by quality gate (correct)")
					return
				}
				t.Errorf("[%s/%s] identify errored: %v", dim, label, err)
				return
			}
			if !r.IsIdentified {
				observe(dim, label+": not identified (correctly rejected)")
				return
			}
			// INV-NOBYPASS: the returned identity must be the enrolled one.
			if r.MatchedEmployeeId != wantID {
				t.Errorf("[%s/%s] INV-NOBYPASS: probe resolved to %s, expected %s (top score %.2f)",
					dim, label, r.MatchedEmployeeId, wantID, r.TopScore)
			}
			// INV-MARGIN: a 1:N answer needs separation from the runner-up.
			if len(r.Candidates) > 1 {
				top := r.Candidates[0].Score
				second := r.Candidates[1].Score
				if len(r.Candidates) > 1 && top-second < 5.0 {
					observe(dim, fmt.Sprintf("%s: LOW MARGIN top=%.2f second=%.2f (ambiguous)", label, top, second))
				}
			}
			observe(dim, label+": identified as "+r.MatchedEmployeeId+" score="+itoa(r.TopScore))
		})
	}

	for i, img := range corpus {
		probe("identical-"+ids[i], img, ids[i])
		probe("shifted-"+ids[i], Shift(img, imgW, imgH, 3, 0), ids[i])
		probe("noisy-"+ids[i], GaussianNoise(img, 12, int64(i)), ids[i])
		probe("rotated-"+ids[i], Rotate(img, imgW, imgH, 4), ids[i])
	}

	// An unseen stranger must not be identified as anyone.
	stranger := LoopPrint(imgW, imgH, 60, 130, 11.5, 987654)
	probe("stranger", stranger, "")
	probe("stranger-shifted", Shift(stranger, imgW, imgH, 4, 4), "")
	probe("stranger-noisy", GaussianNoise(stranger, 10, 5), "")
	probe("stranger-rotated", Rotate(stranger, imgW, imgH, 6), "")

	// Strangers built to clear the quality gate, so the 1:N search itself is
	// exercised rather than short-circuited by the gate.
	for i, seed := range []int64{424242, 515151, 626262, 737373, 848484} {
		s := LoopPrint(imgW, imgH, 70+float64(i)*8, 120-float64(i)*5, 8.0+float64(i)*0.5, seed)
		probe("stranger-quality-"+itoa(float64(i)), s, "")
	}
}

// isQualityRejection reports whether an RPC error is the quality gate doing
// its job rather than a genuine failure.
func isQualityRejection(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "quality") || strings.Contains(m, "NFIQ")
}

// ---------------------------------------------------------------------------
// Expanded degenerate / boundary / resource dimensions
// ---------------------------------------------------------------------------

func TestChaos_DegeneratePatternsExtended(t *testing.T) {
	const dim = "degenerate-patterns"
	c := enrolledCluster(t)

	parallel := func(spacing int) []byte {
		p := make([]byte, imgW*imgH)
		for i := range p {
			p[i] = 200
		}
		for r := spacing; r < imgH-spacing; r += spacing {
			for cc := spacing; cc < imgW-spacing; cc++ {
				p[r*imgW+cc] = 45
			}
		}
		return p
	}
	radial := func() []byte {
		p := make([]byte, imgW*imgH)
		for i := range p {
			p[i] = 205
		}
		for y := 0; y < imgH; y++ {
			for x := 0; x < imgW; x++ {
				r := int(math.Hypot(float64(x)-100, float64(y)-100))
				if r%7 < 3 {
					p[y*imgW+x] = 45
				}
			}
		}
		return p
	}

	pairs := []struct {
		name string
		a, b []byte
	}{
		{"par5-vs-par9", parallel(5), parallel(9)},
		{"par6-vs-par10", parallel(6), parallel(10)},
		{"par7-vs-par12", parallel(7), parallel(12)},
		{"par4-vs-par14", parallel(4), parallel(14)},
		{"par8-vs-par8", parallel(8), parallel(8)},
		{"par3-vs-par20", parallel(3), parallel(20)},
		{"par6-vs-radial", parallel(6), radial()},
		{"radial-vs-par7", radial(), parallel(7)},
	}

	for _, pr := range pairs {
		t.Run(pr.name, func(t *testing.T) {
			record(dim, pr.name)
			ctx, cancel := ctxFor(t, 40*time.Second)
			defer cancel()
			id := "DG-" + pr.name
			if _, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: id, FullName: "DG", Position: genPos,
				ImageRawGray: pr.a, Width: imgW, Height: imgH, Dpi: 500}); err != nil {
				return
			}
			r := verifyProbe(t, c, id, pr.b, imgW, imgH)
			if r.err != nil {
				return
			}
			if r.match {
				observe(dim, "SATURATION: "+pr.name+" accepted a structurally different degenerate pattern, score="+itoa(r.score))
			} else {
				observe(dim, pr.name+" rejected, score="+itoa(r.score))
			}
		})
	}
}

func TestChaos_LargeImagesExtended(t *testing.T) {
	const dim = "resource-large-image"
	c := NewBioCluster(t)
	for _, sz := range []int{160, 200, 240, 280, 320, 360, 400, 440, 480, 512} {
		sz := sz
		t.Run("size", func(t *testing.T) {
			record(dim, "size-"+itoa(float64(sz)))
			img := LoopPrint(sz, sz, float64(sz)*0.5, float64(sz)*0.5, 8.0, int64(sz))
			ctx, cancel := ctxFor(t, 90*time.Second)
			defer cancel()
			t0 := time.Now()
			r, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "BG-" + itoa(float64(sz)), FullName: "BG", Position: genPos,
				ImageRawGray: img, Width: uint32(sz), Height: uint32(sz), Dpi: 500})
			el := time.Since(t0)
			if err != nil {
				observe(dim, fmt.Sprintf("%dx%d rejected after %dms", sz, sz, el.Milliseconds()))
				return
			}
			observe(dim, fmt.Sprintf("%dx%d enrolled in %dms, minutiae=%d, nfiq=%d",
				sz, sz, el.Milliseconds(), r.MinutiaeCount, r.NfiqQualityScore))
			record(dim, "size-"+itoa(float64(sz))+"/done")

			// INV-BOUNDED: no single request may run away.
			if el > 60*time.Second {
				t.Errorf("[%s] INV-BOUNDED: %dx%d enrolment took %dms", dim, sz, sz, el.Milliseconds())
			}
		})
	}
}

func TestChaos_SustainedLoadExtended(t *testing.T) {
	const dim = "resource-sustained"
	c := enrolledCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for _, concurrency := range []int{1, 8, 32, 64, 128} {
		concurrency := concurrency
		t.Run("concurrency", func(t *testing.T) {
			record(dim, "concurrency-"+itoa(float64(concurrency)))
			var wg sync.WaitGroup
			var mu sync.Mutex
			lat := make([]time.Duration, 0, concurrency)
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx, cancel := ctxFor(t, 120*time.Second)
					defer cancel()
					t0 := time.Now()
					_, _ = c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
						EmployeeId: genEmp, Position: genPos,
						ProbeImageRawGray: img, Width: imgW, Height: imgH})
					mu.Lock()
					lat = append(lat, time.Since(t0))
					mu.Unlock()
				}()
			}
			wg.Wait()
			var sum, max time.Duration
			for _, d := range lat {
				sum += d
				if d > max {
					max = d
				}
			}
			avg := sum / time.Duration(len(lat))
			observe(dim, fmt.Sprintf("concurrency=%-4d avg=%-7dms max=%-7dms", concurrency, avg.Milliseconds(), max.Milliseconds()))
			if avg > 15*time.Second {
				t.Errorf("[%s] INV-BOUNDED: avg latency %dms at concurrency %d", dim, avg.Milliseconds(), concurrency)
			}
		})
	}
}

func TestChaos_ContextVariants(t *testing.T) {
	const dim = "dependency-context"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	deadlines := []time.Duration{
		time.Nanosecond, time.Microsecond, time.Millisecond, 5 * time.Millisecond,
		50 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second,
	}
	for i, d := range deadlines {
		t.Run("deadline", func(t *testing.T) {
			record(dim, "deadline-"+itoa(float64(i)))
			ctx, cancel := contextWithDeadline(d)
			defer cancel()
			_, err := c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
				EmployeeId: genEmp, Position: genPos,
				ProbeImageRawGray: img, Width: imgW, Height: imgH})
			observe(dim, fmt.Sprintf("deadline %dms -> %v", d.Milliseconds(), err != nil))
		})
	}

	record(dim, "nil-image-enroll")
	ctx, cancel := ctxFor(t, 10*time.Second)
	defer cancel()
	_, _ = c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
		EmployeeId: "NILIMG", FullName: "N", Position: genPos,
		ImageRawGray: nil, Width: 0, Height: 0, Dpi: 0})
}

// Repeated scans of the same turnstile exercise the audit path and the
// relay decision under repetition.
func TestChaos_RepeatedScanAudit(t *testing.T) {
	const dim = "resource-audit"
	c := NewFullCluster(t)
	img := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	for i := 0; i < 60; i++ {
		t.Run("scan", func(t *testing.T) {
			record(dim, "scan-"+itoa(float64(i)))
			ctx, cancel := ctxFor(t, 20*time.Second)
			defer cancel()
			r, err := c.Edge.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
				TurnstileId: "t", ZoneId: "zone-main-gate",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
				EmployeeId:        fmt.Sprintf("AUD-%d", i),
				ProbeImageRawGray: img, ImageWidth: imgW, ImageHeight: imgH,
				ScanTimestampUnix: time.Now().Unix()})
			if err != nil {
				return
			}
			// Never-enrolled identity must never open the door.
			if r.IsAccessGranted {
				t.Errorf("[%s] INV-NOBYPASS: door opened for never-enrolled identity on scan %d", dim, i)
			}
		})
	}

	// Status endpoint under repeated polling.
	for i := 0; i < 30; i++ {
		t.Run("status", func(t *testing.T) {
			record(dim, "status-"+itoa(float64(i)))
			ctx, cancel := ctxFor(t, 10*time.Second)
			defer cancel()
			if _, err := c.Edge.GetTurnstileStatus(ctx, &edgegatewayv1.GetTurnstileStatusRequest{
				TurnstileId: "t"}); err != nil {
				observe(dim, "status errored: "+shortErr(err))
			}
		})
	}
}
