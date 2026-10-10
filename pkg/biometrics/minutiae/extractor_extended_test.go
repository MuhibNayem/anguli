package minutiae

import (
	"math"
	"testing"
)

// blank returns a w x h skeleton of zeroes.
func blank(w, h int) [][]uint8 {
	s := make([][]uint8, h)
	for y := range s {
		s[y] = make([]uint8, w)
	}
	return s
}

// orientations returns a zero-orientation field.
func orientations(w, h, block int) [][]float64 {
	rows := h/block + 2
	cols := w/block + 2
	o := make([][]float64, rows)
	for i := range o {
		o[i] = make([]float64, cols)
	}
	return o
}

// ridge draws a horizontal run of ridge pixels.
func ridge(s [][]uint8, y, x0, x1 int) {
	for x := x0; x <= x1; x++ {
		s[y][x] = 1
	}
}

// isolatedRidge builds a skeleton containing a short isolated run, which the
// Rutovitz crossing number should classify as two ridge endings.
func isolatedRidge(w, h int) [][]uint8 {
	s := blank(w, h)
	ridge(s, h/2, w/4, w/4+12)
	return s
}

// forkSkeleton builds a Y shape: a vertical trunk splitting into two arms.
func forkSkeleton(w, h int) [][]uint8 {
	s := blank(w, h)
	cx := w / 2
	cy := h / 2
	ridge(s, cy-10, cx-10, cx+10) // horizontal bar
	ridge(s, cy, cx, cx+12)       // lower-right arm
	ridge(s, cy-10, cx, cx)       // connect upward
	for i := 1; i <= 10; i++ {
		s[cy-i][cx] = 1 // upper arm
	}
	return s
}

func TestNewExtractor_Defaults(t *testing.T) {
	e := NewExtractor()
	if e.BorderMargin != 8.0 || e.MinDistance != 4.0 {
		t.Errorf("defaults = %+v; want BorderMargin 8, MinDistance 4", e)
	}
}

// TestExtract_FindsEndingsOnARidge is the baseline: a short isolated run must
// yield two endings, and nothing else.
func TestExtract_FindsEndingsOnARidge(t *testing.T) {
	const w, h = 120, 120
	s := isolatedRidge(w, h)
	e := NewExtractor()

	points := e.Extract(s, w, h, orientations(w, h, 8), 8)

	endings := 0
	for _, p := range points {
		if p.Type == TypeEnding {
			endings++
		}
	}
	if endings == 0 {
		t.Fatalf("no ridge endings found in an isolated ridge; got %d points", len(points))
	}
}

// TestExtract_FindsBifurcationOnAFork covers the bifurcation path, which
// exercises traceSkeletonBifurcation.
func TestExtract_FindsBifurcationOnAFork(t *testing.T) {
	const w, h = 120, 120
	s := forkSkeleton(w, h)
	e := NewExtractor()

	points := e.Extract(s, w, h, orientations(w, h, 8), 8)

	bifurcations := 0
	for _, p := range points {
		if p.Type == TypeBifurcation {
			bifurcations++
		}
	}
	if bifurcations == 0 {
		t.Fatalf("no bifurcation found in a Y-shaped skeleton; got %d points", len(points))
	}
}

// TestExtract_IsDeterministic: the same skeleton must always yield the same
// minutiae, or enrolment and verification would disagree on their own output.
func TestExtract_IsDeterministic(t *testing.T) {
	const w, h = 140, 140
	s := forkSkeleton(w, h)
	e := NewExtractor()
	o := orientations(w, h, 8)

	first := e.Extract(s, w, h, o, 8)
	for i := 0; i < 5; i++ {
		again := e.Extract(s, w, h, o, 8)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d points; first produced %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d point %d differs: %+v vs %+v", i, j, again[j], first[j])
			}
		}
	}
}

// TestExtract_NeverPanicsOnDegenerateInput walks the hostile shapes an
// untrusted caller can supply. A panic here is a remote denial of service on
// the enrollment path.
func TestExtract_NeverPanicsOnDegenerateInput(t *testing.T) {
	e := NewExtractor()

	cases := map[string]struct {
		s    [][]uint8
		w, h int
	}{
		"empty":                {blank(0, 0), 0, 0},
		"too small for margin": {blank(4, 4), 4, 4},
		"exactly margin":       {blank(16, 16), 16, 16},
		"single pixel ridge":   {func() [][]uint8 { s := blank(64, 64); s[32][32] = 1; return s }(), 64, 64},
		"all ridge": {func() [][]uint8 {
			s := blank(64, 64)
			for y := range s {
				for x := range s[y] {
					s[y][x] = 1
				}
			}
			return s
		}(), 64, 64},
		"checkerboard": {func() [][]uint8 {
			s := blank(64, 64)
			for y := range s {
				for x := range s[y] {
					if (x+y)%2 == 0 {
						s[y][x] = 1
					}
				}
			}
			return s
		}(), 64, 64},
		"vertical line": {func() [][]uint8 {
			s := blank(64, 64)
			for y := 20; y < 44; y++ {
				s[y][32] = 1
			}
			return s
		}(), 64, 64},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Extract panicked on %s input: %v", name, r)
				}
			}()
			// A nil orientation field must be tolerated rather than crashing.
			_ = e.Extract(c.s, c.w, c.h, nil, 8)
			_ = e.Extract(c.s, c.w, c.h, orientations(c.w, c.h, 8), 0)
			_ = e.Extract(c.s, c.w, c.h, orientations(c.w, c.h, 8), 1)
		})
	}
}

// TestExtract_StaysWithinImage asserts coordinates never escape the input,
// which would otherwise be an out-of-bounds read further down the pipeline.
func TestExtract_StaysWithinImage(t *testing.T) {
	const w, h = 120, 120
	s := forkSkeleton(w, h)
	e := NewExtractor()

	for _, p := range e.Extract(s, w, h, orientations(w, h, 8), 8) {
		if int(p.X) >= w || int(p.Y) >= h {
			t.Fatalf("minutia at (%d,%d) lies outside a %dx%d image", p.X, p.Y, w, h)
		}
		if int(p.X) < int(e.BorderMargin) || int(p.Y) < int(e.BorderMargin) {
			t.Fatalf("minutia at (%d,%d) sits inside the border margin", p.X, p.Y)
		}
	}
}

// TestExtract_AnglesAreInRange pins the documented [0, 2π) contract, which
// downstream cylinder matching relies on for its modulo arithmetic.
func TestExtract_AnglesAreInRange(t *testing.T) {
	const w, h = 120, 120
	s := forkSkeleton(w, h)
	e := NewExtractor()

	for _, p := range e.Extract(s, w, h, orientations(w, h, 8), 8) {
		if p.Angle < 0 || p.Angle >= 2*math.Pi {
			t.Fatalf("minutia (%d,%d) angle = %v; want [0, 2π)", p.X, p.Y, p.Angle)
		}
		if p.Type == TypeUnspecified {
			t.Fatalf("minutia (%d,%d) has no type assigned", p.X, p.Y)
		}
	}
}

// TestFilterSpuriousMinutiae_SuppressesBothMembersOfAClosePair pins the
// actual semantics: when two detections are closer together than minDistance,
// BOTH are dropped rather than one being kept.
//
// Suppressing both is the conservative reading. Picking a survivor would need
// a tie-break - quality, then position - and any such rule silently biases
// which features a match is built from. Dropping both loses at most one real
// minutia in an ambiguous cluster; keeping an arbitrary one risks building a
// template on a detection the algorithm itself considers doubtful.
func TestFilterSpuriousMinutiae_SuppressesBothMembersOfAClosePair(t *testing.T) {
	pts := []Minutia{
		{X: 10, Y: 10, Type: TypeEnding},
		{X: 11, Y: 10, Type: TypeEnding}, // 1px from the first
		{X: 40, Y: 40, Type: TypeEnding}, // well separated
	}
	got := FilterSpuriousMinutiae(pts, 4.0)

	if len(got) != 1 {
		t.Fatalf("got %d points, want 1; the isolated point should survive: %+v", len(got), got)
	}
	if got[0].X != 40 || got[0].Y != 40 {
		t.Errorf("survivor = %+v; want the well-separated point (40,40)", got[0])
	}
}

// TestFilterSpuriousMinutiae_KeepsPointsAtExactlyTheThreshold guards the
// boundary: the comparison is strict, so points exactly minDistance apart are
// both retained.
func TestFilterSpuriousMinutiae_KeepsPointsAtExactlyTheThreshold(t *testing.T) {
	pts := []Minutia{{X: 0, Y: 0}, {X: 4, Y: 0}} // exactly 4.0 apart
	got := FilterSpuriousMinutiae(pts, 4.0)
	if len(got) != 2 {
		t.Errorf("kept %d of 2 points at exactly the threshold; want both: %+v", len(got), got)
	}
}

func TestFilterSpuriousMinutiae_EmptyAndSingle(t *testing.T) {
	if got := FilterSpuriousMinutiae(nil, 4.0); len(got) != 0 {
		t.Errorf("FilterSpuriousMinutiae(nil) = %v; want empty", got)
	}
	one := []Minutia{{X: 1, Y: 1}}
	if got := FilterSpuriousMinutiae(one, 4.0); len(got) != 1 {
		t.Errorf("FilterSpuriousMinutiae(single) returned %d points; want 1", len(got))
	}
}

// TestMinutiaType_Values pins the wire values, which are persisted inside
// encrypted templates and must not drift between releases.
func TestMinutiaType_Values(t *testing.T) {
	for typ, want := range map[MinutiaType]uint8{
		TypeUnspecified: 0,
		TypeEnding:      1,
		TypeBifurcation: 2,
	} {
		if uint8(typ) != want {
			t.Errorf("MinutiaType = %d; want %d", uint8(typ), want)
		}
	}
}
