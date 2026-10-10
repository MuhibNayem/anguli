package quality_test

import (
	"testing"

	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/pkg/biometrics/quality"
)

func TestQualityAssessorRejectsFlatFeaturelessImages(t *testing.T) {
	assessor := quality.NewQualityAssessor()

	// 1. Completely flat uniform image (all pixels = 128)
	flatPix := make([]byte, 200*200)
	for i := range flatPix {
		flatPix[i] = 128
	}
	flatImg, err := image.NewGrayImage(200, 200, flatPix)
	if err != nil {
		t.Fatalf("failed to create image: %v", err)
	}

	score, acceptable := assessor.Evaluate(flatImg, nil)
	if acceptable || score != 0 {
		t.Errorf("expected flat image to be rejected with score 0, got score=%d, acceptable=%v", score, acceptable)
	}

	// 2. Uniform image with artificial minutiae provided (must still reject due to lack of contrast/energy)
	fakeMinutiae := make([]minutiae.Minutia, 30)
	for i := range fakeMinutiae {
		fakeMinutiae[i] = minutiae.Minutia{X: uint16(i * 5), Y: uint16(i * 5), Angle: 1.0, Type: minutiae.TypeEnding, Quality: 90}
	}
	scoreWithPts, acceptableWithPts := assessor.Evaluate(flatImg, fakeMinutiae)
	if acceptableWithPts || scoreWithPts != 0 {
		t.Errorf("expected flat image with fake minutiae to be rejected, got score=%d, acceptable=%v", scoreWithPts, acceptableWithPts)
	}
}

func TestQualityAssessorAcceptsRealisticFingerprint(t *testing.T) {
	assessor := quality.NewQualityAssessor()
	w, h := 140, 140
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 200
	}
	for r := 20; r < h-20; r += 6 {
		for c := 20; c < w-20; c++ {
			if c%28 == 0 {
				continue
			}
			if (r+c)%45 == 0 && r+3 < h-20 {
				pix[(r+2)*w+c] = 40
			}
			pix[r*w+c] = 40
			if r+1 < h {
				pix[(r+1)*w+c] = 50
			}
		}
	}

	img, err := image.NewGrayImage(w, h, pix)
	if err != nil {
		t.Fatal(err)
	}
	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(15)
	skel := image.ZhangSuenThinning(bin, w, h)
	ori := norm.OrientationField(16)
	ext := minutiae.NewExtractor()
	pts := ext.Extract(skel, w, h, ori, 16)

	score, acceptable := assessor.Evaluate(norm, pts)
	if !acceptable || score < 65 {
		t.Errorf("expected realistic fingerprint to pass with score >= 65, got score=%d, acceptable=%v", score, acceptable)
	}
}
