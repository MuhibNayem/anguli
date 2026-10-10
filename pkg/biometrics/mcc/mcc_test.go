package mcc_test

import (
	"context"
	"math"
	"testing"

	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
)

func TestMCCGenerationAndMatching(t *testing.T) {
	// Generate synthetic minutiae set
	pointsA := []minutiae.Minutia{
		{X: 100, Y: 100, Angle: 0.5, Type: minutiae.TypeEnding, Quality: 90},
		{X: 120, Y: 110, Angle: 0.6, Type: minutiae.TypeBifurcation, Quality: 85},
		{X: 140, Y: 105, Angle: 0.4, Type: minutiae.TypeEnding, Quality: 88},
		{X: 110, Y: 150, Angle: 1.2, Type: minutiae.TypeEnding, Quality: 92},
		{X: 135, Y: 160, Angle: 1.1, Type: minutiae.TypeBifurcation, Quality: 80},
	}

	// Slightly perturbed identical print (simulating minor elastic deformation and rotation)
	pointsB := []minutiae.Minutia{
		{X: 102, Y: 101, Angle: 0.52, Type: minutiae.TypeEnding, Quality: 90},
		{X: 121, Y: 111, Angle: 0.59, Type: minutiae.TypeBifurcation, Quality: 85},
		{X: 139, Y: 104, Angle: 0.41, Type: minutiae.TypeEnding, Quality: 88},
		{X: 111, Y: 149, Angle: 1.18, Type: minutiae.TypeEnding, Quality: 92},
		{X: 136, Y: 159, Angle: 1.12, Type: minutiae.TypeBifurcation, Quality: 80},
	}

	// Completely different imposter print
	pointsImposter := []minutiae.Minutia{
		{X: 300, Y: 300, Angle: 2.5, Type: minutiae.TypeEnding, Quality: 90},
		{X: 350, Y: 310, Angle: 2.8, Type: minutiae.TypeBifurcation, Quality: 85},
		{X: 370, Y: 305, Angle: 3.1, Type: minutiae.TypeEnding, Quality: 88},
		{X: 320, Y: 350, Angle: 0.2, Type: minutiae.TypeEnding, Quality: 92},
		{X: 345, Y: 360, Angle: 0.1, Type: minutiae.TypeBifurcation, Quality: 80},
	}

	tmplA := mcc.BuildTemplate("probe-A", pointsA)
	tmplB := mcc.BuildTemplate("gallery-genuine", pointsB)
	tmplImp := mcc.BuildTemplate("gallery-imposter", pointsImposter)

	matcher := mcc.NewMatcher(0.35, 60.0, nil)

	ctx := context.Background()

	// Test genuine match
	resGenuine, err := matcher.Verify(ctx, tmplA, tmplB)
	if err != nil {
		t.Fatalf("unexpected error during genuine verify: %v", err)
	}

	if !resGenuine.IsMatch {
		t.Errorf("expected genuine match to succeed, got score: %f", resGenuine.Score)
	}

	if resGenuine.Score < 60.0 {
		t.Errorf("expected high similarity for genuine match, got: %f", resGenuine.Score)
	}

	// Test imposter match
	resImposter, err := matcher.Verify(ctx, tmplA, tmplImp)
	if err != nil {
		t.Fatalf("unexpected error during imposter verify: %v", err)
	}

	if resImposter.IsMatch {
		t.Errorf("expected imposter match to be rejected, got score: %f", resImposter.Score)
	}

	// Test serialization round-trip
	bytes := tmplA.SerializeAll()
	deserializedCyls, err := mcc.DeserializeAll(bytes)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	if len(deserializedCyls) != len(tmplA.Cylinders) {
		t.Errorf("expected %d cylinders, got %d", len(tmplA.Cylinders), len(deserializedCyls))
	}

	for i := range tmplA.Cylinders {
		if deserializedCyls[i].MinutiaX != tmplA.Cylinders[i].MinutiaX ||
			deserializedCyls[i].MinutiaY != tmplA.Cylinders[i].MinutiaY ||
			math.Abs(deserializedCyls[i].Angle-tmplA.Cylinders[i].Angle) > 1e-6 {
			t.Errorf("mismatch at cylinder %d", i)
		}
	}
}
