package chaos

import (
	"math"
	"strconv"
	"testing"
	"time"

	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
)

const (
	imgW    = 200
	imgH    = 200
	genEmp  = "CHAOS-GENUINE"
	genPos  = biometricsv1.FingerPosition_FINGER_POSITION_RIGHT_INDEX
	imgSeed = int64(11)
)

type probeResult struct {
	score   float64
	match   bool
	nfiq    uint32
	err     error
	elapsed time.Duration
}

// verifyProbe drives the real gRPC VerifyFingerprint surface.
func verifyProbe(t *testing.T, c *Cluster, emp string, pix []byte, w, h uint32) probeResult {
	t.Helper()
	ctx, cancel := ctxFor(t, 20*time.Second)
	defer cancel()
	t0 := time.Now()
	r, err := c.Bio.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
		EmployeeId:        emp,
		Position:          genPos,
		ProbeImageRawGray: pix,
		Width:             w,
		Height:            h,
	})
	res := probeResult{elapsed: time.Since(t0)}
	if err != nil {
		res.err = err
		return res
	}
	res.score = r.Score
	res.match = r.IsMatch
	res.nfiq = r.NfiqQualityScore
	return res
}

// enrolledCluster returns a cluster with the genuine print enrolled.
func enrolledCluster(t *testing.T) *Cluster {
	t.Helper()
	c := NewBioCluster(t)
	ctx, cancel := ctxFor(t, 30*time.Second)
	defer cancel()
	if _, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
		EmployeeId:   genEmp,
		FullName:     "Chaos Genuine",
		Position:     genPos,
		ImageRawGray: LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed),
		Width:        imgW,
		Height:       imgH,
		Dpi:          500,
	}); err != nil {
		t.Fatalf("enroll baseline: %v", err)
	}
	return c
}

// assertNoFalseAccept is the hard security invariant INV-NOBYPASS: a probe
// derived from a structurally different print must never be accepted, no
// matter how it is degraded.
func assertNoFalseAccept(t *testing.T, dim, name string, r probeResult) {
	t.Helper()
	if r.err != nil {
		return // rejected at the transport layer, also safe
	}
	if r.match {
		t.Errorf("[%s/%s] INV-NOBYPASS VIOLATED: imposter accepted with score %.2f (nfiq %d)",
			dim, name, r.score, r.nfiq)
		return
	}
	observe(dim, name+": imposter rejected, score "+itoa(r.score))
}

func itoa(v float64) string {
	return trimFloat(v)
}

// trimFloat renders a score for the observation ledger: one decimal place
// below 10, truncated to a whole number at or above 10.
//
// This deliberately does NOT hand-roll the digits. An earlier version did
// (`byte('0'+int(v/10))` and friends) and silently mis-rendered any value
// needing three or more digits: 100 came out as ":0", because '0'+10 is ':'
// rather than a digit. That corrupts the ledger, which is the evidence this
// suite exists to produce, so the formatting is delegated to strconv.
func trimFloat(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	neg := math.Signbit(v)
	if neg {
		v = -v
	}
	var s string
	if v < 10 {
		s = strconv.FormatFloat(v, 'f', 1, 64)
	} else {
		s = strconv.FormatFloat(math.Trunc(v), 'f', -1, 64)
	}
	if neg {
		return "-" + s
	}
	return s
}

// ---------------------------------------------------------------------------
// Image degradation chaos
// ---------------------------------------------------------------------------

func TestChaos_ImageDegradation(t *testing.T) {
	const dim = "image-degradation"
	c := enrolledCluster(t)
	gen := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)
	// IMP-C1: an imposter cohort of structurally distinct, non-degenerate prints.
	impCohort := LoopCorpus(imgW, imgH, 3)
	imp := impCohort[0]

	type scenario struct {
		name string
		gen  []byte
		imp  []byte
	}

	var scenarios []scenario

	// --- Gaussian blur sweep ---
	for _, s := range []float64{0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0} {
		scenarios = append(scenarios, scenario{
			name: "blur-" + ftoa(s),
			gen:  GaussianBlur(gen, imgW, imgH, s),
			imp:  GaussianBlur(imp, imgW, imgH, s),
		})
	}

	// --- Contrast collapse sweep (oily finger) ---
	for _, c2 := range []float64{1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05, 0.01} {
		scenarios = append(scenarios, scenario{
			name: "oily-contrast-" + ftoa(c2),
			gen:  Oily(gen, imgW, imgH, 1.0, c2),
			imp:  Oily(imp, imgW, imgH, 1.0, c2),
		})
	}

	// --- Additive Gaussian noise sweep ---
	for _, s := range []float64{2, 5, 8, 12, 16, 20, 25, 30, 40, 50, 70, 100} {
		scenarios = append(scenarios, scenario{
			name: "noise-" + ftoa(s),
			gen:  GaussianNoise(gen, s, imgSeed),
			imp:  GaussianNoise(imp, s, imgSeed),
		})
	}

	// --- Ridge erosion sweep (dry finger) ---
	for _, p := range []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95} {
		scenarios = append(scenarios, scenario{
			name: "dry-erosion-" + ftoa(p),
			gen:  Dry(gen, 110, p, imgSeed),
			imp:  Dry(imp, 110, p, imgSeed),
		})
	}

	// --- Partial print sweep (half finger etc) ---
	for _, f := range []float64{1.0, 0.95, 0.9, 0.85, 0.8, 0.7, 0.6, 0.5, 0.4, 0.35, 0.3, 0.25, 0.2, 0.15, 0.1, 0.05} {
		scenarios = append(scenarios, scenario{
			name: "partial-" + ftoa(f),
			gen:  Partial(gen, imgW, imgH, f),
			imp:  Partial(imp, imgW, imgH, f),
		})
	}

	// --- Rotation sweep ---
	for _, d := range []float64{0, 0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 7, 10, 15, 20, 25, 30, 45, 90, 180, 270} {
		scenarios = append(scenarios, scenario{
			name: "rotate-" + ftoa(d),
			gen:  Rotate(gen, imgW, imgH, d),
			imp:  Rotate(imp, imgW, imgH, d),
		})
	}

	// --- Translation sweep ---
	for _, d := range []int{0, 1, 2, 3, 4, 6, 8, 12, -4, -8} {
		scenarios = append(scenarios, scenario{
			name: "shift-" + itoa(float64(d)),
			gen:  Shift(gen, imgW, imgH, d, d),
			imp:  Shift(imp, imgW, imgH, d, d),
		})
	}

	// --- Motion blur sweep ---
	for _, s := range []int{2, 3, 4, 5, 6, 8, 10, 14} {
		scenarios = append(scenarios, scenario{
			name: "motion-" + itoa(float64(s)),
			gen:  MotionBlur(gen, imgW, imgH, s),
			imp:  MotionBlur(imp, imgW, imgH, s),
		})
	}

	// --- Wet finger: blur + specular at several positions ---
	for _, sp := range [][3]float64{{95, 80, 34}, {40, 40, 30}, {100, 30, 25}, {60, 110, 40}, {30, 90, 20}} {
		scenarios = append(scenarios, scenario{
			name: "wet-specular-" + ftoa(sp[0]) + "-" + ftoa(sp[1]),
			gen:  Wet(gen, imgW, imgH, 1.2, sp[0], sp[1], sp[2]),
			imp:  Wet(imp, imgW, imgH, 1.2, sp[0], sp[1], sp[2]),
		})
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			record(dim, sc.name+"/genuine")
			record(dim, sc.name+"/imposter")

			gr := verifyProbe(t, c, genEmp, sc.gen, imgW, imgH)
			if gr.err != nil {
				t.Errorf("[%s/%s] genuine probe rejected with transport error: %v", dim, sc.name, gr.err)
			} else {
				observe(dim, sc.name+": genuine score="+itoa(gr.score)+" match="+boolStr(gr.match)+" nfiq="+itoa(float64(gr.nfiq)))
			}

			ir := verifyProbe(t, c, genEmp, sc.imp, imgW, imgH)
			assertNoFalseAccept(t, dim, sc.name+"/imposter", ir)
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func ftoa(v float64) string {
	// compact float formatting for test names
	if v == float64(int(v)) {
		return itoa(v)
	}
	return itoa(v)
}
