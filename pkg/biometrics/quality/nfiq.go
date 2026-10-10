package quality

import (
	"math"

	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/minutiae"
)

const (
	// EnterpriseThreshold defines the minimum acceptable NFIQ quality score for enrollment.
	EnterpriseThreshold uint32 = 65
)

// QualityAssessor evaluates biometric image utility and quality following ISO/IEC 29794-4 principles.
type QualityAssessor struct {
	MinAcceptableScore uint32
}

// NewQualityAssessor creates a new quality assessor.
func NewQualityAssessor() *QualityAssessor {
	return &QualityAssessor{
		MinAcceptableScore: EnterpriseThreshold,
	}
}

// Evaluate computes an overall quality score from 0 to 100 based on orientation coherence, contrast, and minutiae distribution.
func (q *QualityAssessor) Evaluate(img *image.GrayImage, points []minutiae.Minutia) (uint32, bool) {
	if img == nil || len(img.Pix) == 0 {
		return 0, false
	}

	// 1. Contrast & Dynamic Range Metric [0.0 - 1.0]
	var sum, varSum float64
	for _, p := range img.Pix {
		sum += float64(p)
	}
	mean := sum / float64(len(img.Pix))
	for _, p := range img.Pix {
		diff := float64(p) - mean
		varSum += diff * diff
	}
	stdDev := math.Sqrt(varSum / float64(len(img.Pix)))

	// Strict Featureless Rejection: An enterprise biometric print must have sufficient contrast
	if stdDev < 15.0 {
		return 0, false
	}

	// Target stdDev for 500 DPI optical/capacitive print is ~40-70
	contrastScore := stdDev / 60.0
	if contrastScore > 1.0 {
		contrastScore = 1.0
	}

	// 2. Ridge Gradient Energy & Orientation Field Coherence [0.0 - 1.0]
	blockSize := 16
	rows := (img.Height + blockSize - 1) / blockSize
	cols := (img.Width + blockSize - 1) / blockSize

	var totalEnergy float64
	var validBlocks int
	blockEnergies := make([][]float64, rows)
	for r := 0; r < rows; r++ {
		blockEnergies[r] = make([]float64, cols)
	}

	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			var gxx, gyy float64
			startY := r * blockSize
			endY := startY + blockSize
			if endY > img.Height-1 {
				endY = img.Height - 1
			}
			startX := c * blockSize
			endX := startX + blockSize
			if endX > img.Width-1 {
				endX = img.Width - 1
			}

			for y := startY + 1; y < endY; y++ {
				for x := startX + 1; x < endX; x++ {
					gx := float64(img.At(x+1, y-1)) + 2.0*float64(img.At(x+1, y)) + float64(img.At(x+1, y+1)) -
						(float64(img.At(x-1, y-1)) + 2.0*float64(img.At(x-1, y)) + float64(img.At(x-1, y+1)))
					gy := float64(img.At(x-1, y+1)) + 2.0*float64(img.At(x, y+1)) + float64(img.At(x+1, y+1)) -
						(float64(img.At(x-1, y-1)) + 2.0*float64(img.At(x, y-1)) + float64(img.At(x+1, y-1)))
					gxx += gx * gx
					gyy += gy * gy
				}
			}
			energy := math.Sqrt(gxx + gyy)
			blockEnergies[r][c] = energy
			totalEnergy += energy
			if energy >= 150.0 { // Minimum ridge edge energy threshold
				validBlocks++
			}
		}
	}

	totalBlocks := rows * cols
	if totalBlocks == 0 || float64(validBlocks)/float64(totalBlocks) < 0.15 {
		// Insufficient ridge flow structure across sensor surface
		return 0, false
	}

	orientations := img.OrientationField(blockSize)

	var coherenceSum float64
	var coherenceCount float64

	for r := 1; r < rows-1; r++ {
		for c := 1; c < cols-1; c++ {
			if blockEnergies[r][c] < 150.0 {
				continue // Skip featureless / background blocks
			}
			thetaCenter := orientations[r][c]
			var neighborDiffSum float64
			var validNeighbors float64

			for dr := -1; dr <= 1; dr++ {
				for dc := -1; dc <= 1; dc++ {
					if dr == 0 && dc == 0 {
						continue
					}
					if blockEnergies[r+dr][c+dc] < 150.0 {
						continue
					}
					diff := math.Abs(thetaCenter - orientations[r+dr][c+dc])
					if diff > math.Pi/2 {
						diff = math.Pi - diff
					}
					neighborDiffSum += diff
					validNeighbors++
				}
			}

			if validNeighbors > 0 {
				avgDiff := neighborDiffSum / validNeighbors
				localCoherence := 1.0 - (avgDiff / (math.Pi / 2.0))
				if localCoherence < 0 {
					localCoherence = 0
				}
				coherenceSum += localCoherence
				coherenceCount++
			}
		}
	}

	orientationScore := 0.0
	if coherenceCount > 0 {
		orientationScore = coherenceSum / coherenceCount
	} else {
		return 0, false
	}

	// 3. Minutiae Plausibility Metric [0.0 - 1.0]
	minutiaeCount := len(points)
	var minutiaeScore float64
	if minutiaeCount >= 20 && minutiaeCount <= 100 {
		minutiaeScore = 1.0
	} else if minutiaeCount < 20 {
		minutiaeScore = float64(minutiaeCount) / 20.0
	} else {
		minutiaeScore = math.Max(0.2, 1.0-float64(minutiaeCount-100)/100.0)
	}

	// Composite Weighted NFIQ Equivalent Score
	rawScore := (contrastScore*0.25 + orientationScore*0.45 + minutiaeScore*0.30) * 100.0
	if rawScore < 0 {
		rawScore = 0
	}
	if rawScore > 100 {
		rawScore = 100
	}

	score := uint32(math.Round(rawScore))
	isAcceptable := score >= q.MinAcceptableScore && minutiaeCount >= 15

	return score, isAcceptable
}
