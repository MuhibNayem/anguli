package chaos

import (
	"testing"
	"time"

	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
)

// ---------------------------------------------------------------------------
// Characterised (non-asserted) finding: degenerate patterns
// ---------------------------------------------------------------------------
//
// A uniform parallel-ridge pattern has no local neighbourhood variation, so
// every MCC cylinder is near-identical and the matcher saturates: it reports
// ~100% matched pairs and scores 93-99 for structurally different inputs.
//
// This is NOT a false-accept vulnerability against realistic fingerprints (the
// corpus used elsewhere in this suite discriminates correctly), but it IS a
// real robustness limit: the matcher has no global spatial-consistency floor,
// so if every local neighbourhood is degenerate it has nothing to disagree
// about. Recorded as a finding rather than an assertion.
func TestChaos_DegeneratePatterns(t *testing.T) {
	const dim = "degenerate-patterns"
	c := enrolledCluster(t)

	parallel := func(w, h, spacing int) []byte {
		p := make([]byte, w*h)
		for i := range p {
			p[i] = 200
		}
		for r := spacing; r < h-spacing; r += spacing {
			for c := spacing; c < w-spacing; c++ {
				p[r*w+c] = 45
			}
		}
		return p
	}

	variants := []struct {
		name string
		gen  []byte
		imp  []byte
	}{
		{"parallel-spacing5", parallel(imgW, imgH, 5), parallel(imgW, imgH, 9)},
		{"parallel-spacing6-vs10", parallel(imgW, imgH, 6), parallel(imgW, imgH, 10)},
		{"parallel-spacing7-vs12", parallel(imgW, imgH, 7), parallel(imgW, imgH, 12)},
		{"parallel-dense-vs-coarse", parallel(imgW, imgH, 4), parallel(imgW, imgH, 14)},
		{"identical-parallel", parallel(imgW, imgH, 8), parallel(imgW, imgH, 8)},
	}

	ctx, cancel := ctxFor(t, 60*time.Second)
	defer cancel()
	for _, v := range variants {
		if _, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
			EmployeeId: "DEG-" + v.name, FullName: "Degenerate",
			Position: genPos, ImageRawGray: v.gen, Width: imgW, Height: imgH, Dpi: 500,
		}); err != nil {
			continue
		}
		record(dim, v.name)
		r := verifyProbe(t, c, "DEG-"+v.name, v.imp, imgW, imgH)
		if r.err != nil {
			continue
		}
		if r.match {
			observe(dim, "SATURATION: "+v.name+" accepted a different parallel-ridge pattern, score="+itoa(r.score))
		} else {
			observe(dim, v.name+" correctly rejected, score="+itoa(r.score))
		}
	}
}

// ---------------------------------------------------------------------------
// Malformed / degenerate image payloads
// ---------------------------------------------------------------------------

func TestChaos_MalformedImages(t *testing.T) {
	const dim = "malformed-image"
	c := NewBioCluster(t)
	good := LoopPrint(imgW, imgH, 95, 105, 9.0, imgSeed)

	cases := []struct {
		name string
		pix  []byte
		w    uint32
		h    uint32
	}{
		{"nil-buffer", nil, imgW, imgH},
		{"empty-buffer", []byte{}, imgW, imgH},
		{"one-byte", []byte{1}, imgW, imgH},
		{"single-byte-buffer", []byte{128}, 1, 1},
		{"buffer-one-short", good[:len(good)-1], imgW, imgH},
		{"buffer-one-long", append(append([]byte{}, good...), 0), imgW, imgH},
		{"buffer-half", good[:len(good)/2], imgW, imgH},
		{"buffer-double", append(append([]byte{}, good...), good...), imgW, imgH},
		{"width-zero", good, 0, imgH},
		{"height-zero", good, imgW, 0},
		{"both-zero", good, 0, 0},
		{"dims-1x1", []byte{128}, 1, 1},
		{"dims-1xN", make([]byte, 200), 1, 200},
		{"dims-Nx1", make([]byte, 200), 200, 1},
		{"dims-2x2", make([]byte, 4), 2, 2},
		{"dims-tiny-3x3", make([]byte, 9), 3, 3},
		{"dims-huge-w-small-buf", good, 1 << 20, 1 << 20},
		{"dims-max-uint32", good, 4294967295, 4294967295},
		{"dims-w-huge-h-1", make([]byte, 64), 1 << 16, 1},
		{"all-zero-pixels", make([]byte, imgW*imgH), imgW, imgH},
		{"all-255-pixels", bytesAll(255, imgW*imgH), imgW, imgH},
		{"all-128-pixels", bytesAll(128, imgW*imgH), imgW, imgH},
		{"all-1-pixels", bytesAll(1, imgW*imgH), imgW, imgH},
		{"all-254-pixels", bytesAll(254, imgW*imgH), imgW, imgH},
		{"checkerboard", checker(imgW, imgH), imgW, imgH},
		{"vertical-stripes", stripes(imgW, imgH, true), imgW, imgH},
		{"horizontal-stripes", stripes(imgW, imgH, false), imgW, imgH},
		{"single-ridge", singleRidge(imgW, imgH), imgW, imgH},
		{"random-bytes", randomBytes(imgW*imgH, 5), imgW, imgH},
		{"random-bytes-2", randomBytes(imgW*imgH, 6), imgW, imgH},
		{"saturated-hi", bytesAll(255, imgW*imgH/4), imgW, imgH / 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record(dim, tc.name+"/verify")
			// INV-NOPANIC / INV-CORRECT: must not panic; must not grant.
			r := verifyProbe(t, c, "NO-SUCH-EMPLOYEE", tc.pix, tc.w, tc.h)
			if r.err == nil && r.match {
				t.Errorf("[%s/%s] INV-NOBYPASS: malformed payload granted access (score %.2f)",
					dim, tc.name, r.score)
			}

			record(dim, tc.name+"/enroll")
			ctx, cancel := ctxFor(t, 10*time.Second)
			defer cancel()
			_, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId:   "MAL-" + tc.name,
				FullName:     "Malformed",
				Position:     genPos,
				ImageRawGray: tc.pix,
				Width:        tc.w,
				Height:       tc.h,
				Dpi:          500,
			})
			if err != nil {
				observe(dim, tc.name+"/enroll rejected: "+shortErr(err))
			} else {
				observe(dim, tc.name+"/enroll ACCEPTED malformed payload")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Boundary image sizes that should still be handled
// ---------------------------------------------------------------------------

func TestChaos_BoundaryDimensions(t *testing.T) {
	const dim = "boundary-dimensions"
	sizes := []struct {
		w, h int
	}{
		{8, 8}, {16, 16}, {24, 24}, {32, 32}, {48, 48},
		{64, 64}, {100, 100}, {128, 128}, {160, 160},
		{240, 240}, {300, 300}, {360, 360},
	}
	nonSquare := []struct{ w, h int }{
		{64, 32}, {32, 64}, {128, 48}, {48, 128}, {200, 100}, {100, 200}, {256, 16},
	}

	c := NewBioCluster(t)

	for _, s := range sizes {
		t.Run("square", func(t *testing.T) {
			record(dim, "square-"+itoa(float64(s.w)))
			img := LoopPrint(s.w, s.h, float64(s.w)*0.5, float64(s.h)*0.5, 8.0, 5)
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			r, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "BD-" + itoa(float64(s.w)), FullName: "B", Position: genPos,
				ImageRawGray: img, Width: uint32(s.w), Height: uint32(s.h), Dpi: 500,
			})
			if err != nil {
				observe(dim, "square-"+itoa(float64(s.w))+" rejected: "+shortErr(err))
				return
			}
			observe(dim, "square-"+itoa(float64(s.w))+" accepted, minutiae="+itoa(float64(r.MinutiaeCount))+" nfiq="+itoa(float64(r.NfiqQualityScore)))
		})
	}

	for _, s := range nonSquare {
		t.Run("rect", func(t *testing.T) {
			record(dim, "rect-"+itoa(float64(s.w))+"x"+itoa(float64(s.h)))
			img := LoopPrint(s.w, s.h, float64(s.w)*0.5, float64(s.h)*0.5, 8.0, 6)
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			_, err := c.Bio.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId: "RC-" + itoa(float64(s.w)) + "-" + itoa(float64(s.h)), FullName: "R",
				Position: genPos, ImageRawGray: img, Width: uint32(s.w), Height: uint32(s.h), Dpi: 500,
			})
			if err != nil {
				observe(dim, "rect-"+itoa(float64(s.w))+"x"+itoa(float64(s.h))+" rejected: "+shortErr(err))
			}
		})
	}
}

func bytesAll(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func checker(w, h int) []byte {
	b := make([]byte, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if (x+y)%2 == 0 {
				b[y*w+x] = 255
			} else {
				b[y*w+x] = 0
			}
		}
	}
	return b
}

func stripes(w, h int, vertical bool) []byte {
	b := make([]byte, w*h)
	for i := range b {
		b[i] = 200
	}
	if vertical {
		for x := 0; x < w; x += 3 {
			for y := 0; y < h; y++ {
				b[y*w+x] = 40
			}
		}
	} else {
		for y := 0; y < h; y += 3 {
			for x := 0; x < w; x++ {
				b[y*w+x] = 40
			}
		}
	}
	return b
}

func singleRidge(w, h int) []byte {
	b := bytesAll(200, w*h)
	for x := 0; x < w; x++ {
		b[(h/2)*w+x] = 40
	}
	return b
}

func randomBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	state := uint64(seed)*6364136223846793005 + 1442695040888963407
	for i := range b {
		state = state*6364136223846793005 + 1442695040888963407
		b[i] = byte(state >> 33)
	}
	return b
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		return s[:90] + "..."
	}
	return s
}
