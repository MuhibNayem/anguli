package image_test

import (
	"testing"

	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/pkg/biometrics/quality"
)

func TestImageEnhancementAndSkeletonization(t *testing.T) {
	width := 64
	height := 64
	pix := make([]uint8, width*height)

	// Draw synthetic vertical and diagonal ridges
	for y := 10; y < 50; y++ {
		// Vertical ridge at x=20
		pix[y*width+20] = 50
		pix[y*width+21] = 40
		pix[y*width+22] = 50

		// Branching diagonal ridge
		if y > 30 {
			pix[y*width+20+(y-30)] = 45
			pix[y*width+21+(y-30)] = 40
		}
	}

	// Fill background
	for i := range pix {
		if pix[i] == 0 {
			pix[i] = 200
		}
	}

	img, err := image.NewGrayImage(width, height, pix)
	if err != nil {
		t.Fatalf("failed to create image: %v", err)
	}

	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(7)
	skel := image.ZhangSuenThinning(bin, width, height)

	if len(skel) != height {
		t.Errorf("expected skeleton height %d, got %d", height, len(skel))
	}

	// Extract minutiae
	extractor := minutiae.NewExtractor()
	extractor.BorderMargin = 4.0
	extractor.MinDistance = 3.0

	points := extractor.Extract(skel, width, height, nil, 8)
	t.Logf("Extracted minutiae points count: %d", len(points))
}

func TestRealisticMinutiaeCount(t *testing.T) {
	w, h := 140, 140
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 200
	}
	for r := 20; r < h-20; r += 6 {
		for c := 20; c < w-20; c++ {
			if (c)%28 == 0 {
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
	extractor := minutiae.NewExtractor()
	pts := extractor.Extract(skel, w, h, nil, 16)
	t.Logf("Realistic print extracted: %d minutiae", len(pts))

	assessor := quality.NewQualityAssessor()
	score, ok := assessor.Evaluate(norm, pts)
	t.Logf("NFIQ score: %d, acceptable: %v", score, ok)
}
