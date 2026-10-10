package minutiae_test

import (
	"math"
	"testing"

	"finger-scanner/pkg/biometrics/minutiae"
)

func TestMinutiaeExtractionAndDirection(t *testing.T) {
	w, h := 64, 64
	skel := make([][]uint8, h)
	for y := 0; y < h; y++ {
		skel[y] = make([]uint8, w)
	}

	// Draw horizontal line from x=10 to x=30 at y=20 (ridge ending at x=30)
	for x := 10; x <= 30; x++ {
		skel[20][x] = 1
	}

	extractor := minutiae.NewExtractor()
	extractor.BorderMargin = 4.0
	extractor.MinDistance = 3.0

	// Block size 8
	pts := extractor.Extract(skel, w, h, nil, 8)
	if len(pts) != 2 {
		t.Fatalf("expected 2 endings (x=10 and x=30), got %d", len(pts))
	}

	// Minutia at x=30 points right (0.0 rad)
	var rightEnding *minutiae.Minutia
	for i := range pts {
		if pts[i].X == 30 {
			rightEnding = &pts[i]
		}
	}
	if rightEnding == nil {
		t.Fatal("expected minutia at x=30")
	}

	// Angle pointing right along horizontal line: 0.0 radians (testing M2 fix: 0.0 is a valid angle!)
	if math.Abs(rightEnding.Angle) > 0.1 && math.Abs(rightEnding.Angle-2*math.Pi) > 0.1 {
		t.Errorf("expected horizontal right ending angle ~0 rad, got %f", rightEnding.Angle)
	}
}

func TestOrderIndependentFilterSpuriousMinutiae(t *testing.T) {
	// Points with two close pairs
	pts1 := []minutiae.Minutia{
		{X: 10, Y: 10, Angle: 0.0, Quality: 80},
		{X: 12, Y: 10, Angle: 0.0, Quality: 80}, // within distance 3.0 of pt 0
		{X: 50, Y: 50, Angle: 1.0, Quality: 85},
	}

	// Same points reversed in slice
	pts2 := []minutiae.Minutia{
		{X: 50, Y: 50, Angle: 1.0, Quality: 85},
		{X: 12, Y: 10, Angle: 0.0, Quality: 80},
		{X: 10, Y: 10, Angle: 0.0, Quality: 80},
	}

	filtered1 := minutiae.FilterSpuriousMinutiae(pts1, 3.0)
	filtered2 := minutiae.FilterSpuriousMinutiae(pts2, 3.0)

	if len(filtered1) != 1 || filtered1[0].X != 50 {
		t.Errorf("expected only point (50, 50) to survive in set 1, got %v", filtered1)
	}
	if len(filtered2) != 1 || filtered2[0].X != 50 {
		t.Errorf("expected only point (50, 50) to survive in set 2, got %v", filtered2)
	}
}
