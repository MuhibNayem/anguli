package mcc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"finger-scanner/pkg/biometrics/minutiae"
)

var (
	ErrEmptyTemplate = errors.New("cannot match with empty template or missing cylinders")
)

// Template represents the full set of cylinders extracted from a fingerprint impression.
type Template struct {
	ID        string     `json:"id"`
	Cylinders []Cylinder `json:"cylinders"`
}

// BuildTemplate converts extracted minutiae points into a complete MCC Template.
func BuildTemplate(id string, points []minutiae.Minutia) *Template {
	cyls := make([]Cylinder, len(points))
	for i, pt := range points {
		cyls[i] = CreateCylinder(pt, points)
	}
	return &Template{
		ID:        id,
		Cylinders: cyls,
	}
}

// MatchVerificationResult contains matching metrics.
type MatchVerificationResult struct {
	IsMatch          bool    `json:"is_match"`
	Score            float64 `json:"score"`
	MatchedPairs     int     `json:"matched_pairs"`
	DurationMicrosec int64   `json:"duration_microsec"`
}

// Matcher performs local similarity sorting and global consensus matching.
type Matcher struct {
	CylinderMatchThreshold float64
	GlobalScoreThreshold   float64
	Logger                 *slog.Logger
}

// NewMatcher creates a production-grade MCC matcher.
func NewMatcher(cylThreshold, globalThreshold float64, logger *slog.Logger) *Matcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Matcher{
		CylinderMatchThreshold: cylThreshold,
		GlobalScoreThreshold:   globalThreshold,
		Logger:                 logger,
	}
}

// Verify compares probe and gallery templates using local similarity sort with spatial consistency.
func (m *Matcher) Verify(ctx context.Context, probe, gallery *Template) (MatchVerificationResult, error) {
	startTime := time.Now()

	if probe == nil || gallery == nil || len(probe.Cylinders) == 0 || len(gallery.Cylinders) == 0 {
		return MatchVerificationResult{IsMatch: false, Score: 0.0}, ErrEmptyTemplate
	}

	type candidatePair struct {
		probeIdx   int
		galleryIdx int
		score      float64
		deltaAngle float64
	}

	// Step 1: Collect candidate pairings with similarity >= threshold
	//
	// Everything the pairwise kernel needs that does not vary per pair is
	// computed once here: the probe's occupied cells and popcount, and the
	// gallery's popcount. A Cylinder is 204 bytes and a walk-up scores every
	// probe cylinder against every gallery cylinder, so the loops are
	// index-based rather than `for _, cyl` - ranging by value copied the whole
	// struct on every inner iteration, which was ~200 MB of memcpy per search.
	probeCells := probeCellSets(probe.Cylinders)
	probePops := make([]int, len(probe.Cylinders))
	for i := range probe.Cylinders {
		probePops[i] = popCount(&probe.Cylinders[i].Bits)
	}
	galleryPops := make([]int, len(gallery.Cylinders))
	for i := range gallery.Cylinders {
		galleryPops[i] = popCount(&gallery.Cylinders[i].Bits)
	}

	var candidates []candidatePair
	for pIdx := range probe.Cylinders {
		pCyl := &probe.Cylinders[pIdx]
		for gIdx := range gallery.Cylinders {
			gCyl := &gallery.Cylinders[gIdx]

			sim := pCyl.Similarity(gCyl)
			// Fast prune: only test angular shift if candidate already exhibits plausible overlap
			if sim < m.CylinderMatchThreshold && sim >= 0.12 {
				shiftedSim := shiftedBest(probeCells[pIdx], gCyl, sim, probePops[pIdx], galleryPops[gIdx], 1)
				if shiftedSim > sim {
					sim = shiftedSim
				}
			}
			if sim >= m.CylinderMatchThreshold {
				dAngle := pCyl.Angle - gCyl.Angle
				for dAngle > math.Pi {
					dAngle -= 2 * math.Pi
				}
				for dAngle < -math.Pi {
					dAngle += 2 * math.Pi
				}
				candidates = append(candidates, candidatePair{
					probeIdx:   pIdx,
					galleryIdx: gIdx,
					score:      sim,
					deltaAngle: dAngle,
				})
			}
		}
	}

	if len(candidates) == 0 {
		duration := time.Since(startTime).Microseconds()
		return MatchVerificationResult{
			IsMatch:          false,
			Score:            0.0,
			MatchedPairs:     0,
			DurationMicrosec: duration,
		}, nil
	}

	// Step 2: Global Angular Consensus Clustering (Hough Voting on rotation angle)
	// In physical turnstile/doorstep biometric readers, presentation is within ±45° (±0.78 rad)
	const maxRotation = math.Pi / 4.0
	const numBins = 36
	type binCluster struct {
		pairs []candidatePair
	}
	bins := make([]binCluster, numBins)

	for _, cand := range candidates {
		if math.Abs(cand.deltaAngle) > maxRotation {
			continue
		}
		a := cand.deltaAngle
		if a < 0 {
			a += 2 * math.Pi
		}
		binIdx := int(a / (2 * math.Pi / float64(numBins)))
		if binIdx >= numBins {
			binIdx = numBins - 1
		}
		bins[binIdx].pairs = append(bins[binIdx].pairs, cand)
	}

	bestCount := 0
	bestBin := 0
	for i := 0; i < numBins; i++ {
		prev := (i - 1 + numBins) % numBins
		next := (i + 1) % numBins
		combined := len(bins[prev].pairs) + len(bins[i].pairs) + len(bins[next].pairs)
		if combined > bestCount {
			bestCount = combined
			bestBin = i
		}
	}

	if bestCount == 0 {
		duration := time.Since(startTime).Microseconds()
		return MatchVerificationResult{
			IsMatch:          false,
			Score:            0.0,
			MatchedPairs:     0,
			DurationMicrosec: duration,
		}, nil
	}

	prevBin := (bestBin - 1 + numBins) % numBins
	nextBin := (bestBin + 1) % numBins

	var angleConsensus []candidatePair
	angleConsensus = append(angleConsensus, bins[bestBin].pairs...)
	angleConsensus = append(angleConsensus, bins[prevBin].pairs...)
	angleConsensus = append(angleConsensus, bins[nextBin].pairs...)

	// Compute average consensus rotation angle Phi
	var sinSum, cosSum float64
	for _, p := range angleConsensus {
		sinSum += math.Sin(p.deltaAngle)
		cosSum += math.Cos(p.deltaAngle)
	}
	consensusPhi := math.Atan2(sinSum, cosSum)
	cosPhi := math.Cos(consensusPhi)
	sinPhi := math.Sin(consensusPhi)

	// Step 3: Spatial Translation Clustering under consensus rotation Phi
	type transPair struct {
		candidatePair
		tx, ty float64
	}
	transPairs := make([]transPair, 0, len(angleConsensus))
	for _, p := range angleConsensus {
		gx := float64(gallery.Cylinders[p.galleryIdx].MinutiaX)
		gy := float64(gallery.Cylinders[p.galleryIdx].MinutiaY)
		rotGx := gx*cosPhi - gy*sinPhi
		rotGy := gx*sinPhi + gy*cosPhi

		px := float64(probe.Cylinders[p.probeIdx].MinutiaX)
		py := float64(probe.Cylinders[p.probeIdx].MinutiaY)

		tx := px - rotGx
		ty := py - rotGy
		transPairs = append(transPairs, transPair{candidatePair: p, tx: tx, ty: ty})
	}

	const transTol = 14.0
	type gridKey struct {
		gx, gy int
	}
	grid := make(map[gridKey][]transPair, len(transPairs))
	for _, tp := range transPairs {
		k := gridKey{
			gx: int(math.Floor(tp.tx / transTol)),
			gy: int(math.Floor(tp.ty / transTol)),
		}
		grid[k] = append(grid[k], tp)
	}

	bestInliers := 0
	var bestInlierPairs []transPair
	bestKey := gridKey{}
	bestClusterScore := 0.0
	for k := range grid {
		var cluster []transPair
		for dx := -1; dx <= 1; dx++ {
			for dy := -1; dy <= 1; dy++ {
				nk := gridKey{gx: k.gx + dx, gy: k.gy + dy}
				if pts, ok := grid[nk]; ok {
					cluster = append(cluster, pts...)
				}
			}
		}

		// Tie-breaks here are load-bearing, not decoration.
		//
		// Go randomises map iteration order, so taking the first cluster of
		// maximum size made the result depend on the runtime rather than on the
		// inputs. Measured on random templates, the same probe against the same
		// finger returned a different score on repeated calls in roughly half
		// of all trials.
		//
		// For an access control decision that is not a cosmetic defect: a
		// score near the threshold cannot be reproduced, an incident cannot be
		// reconstructed from the captured template, and a flaky test cannot
		// distinguish a regression from map ordering.
		//
		// The order of preference is therefore: most inliers, then the cluster
		// containing the best cylinder similarity, then the lexicographically
		// smallest grid key. Every step is total, so the choice is a function of
		// the inputs and nothing else.
		clusterScore := 0.0
		for _, tp := range cluster {
			if tp.score > clusterScore {
				clusterScore = tp.score
			}
		}

		better := false
		switch {
		case len(cluster) > bestInliers:
			better = true
		case len(cluster) < bestInliers:
			better = false
		case clusterScore > bestClusterScore:
			better = true
		case clusterScore < bestClusterScore:
			better = false
		default:
			better = k.gx < bestKey.gx || (k.gx == bestKey.gx && k.gy < bestKey.gy)
		}

		if better {
			bestInliers = len(cluster)
			bestInlierPairs = cluster
			bestKey = k
			bestClusterScore = clusterScore
		}
	}

	// Step 4: Sort spatial-angular inliers by similarity score and assign 1:1
	sort.Slice(bestInlierPairs, func(i, j int) bool {
		return bestInlierPairs[i].score > bestInlierPairs[j].score
	})

	usedProbe := make(map[int]bool, len(probe.Cylinders))
	usedGallery := make(map[int]bool, len(gallery.Cylinders))
	var matchedScores []float64

	for _, tip := range bestInlierPairs {
		if usedProbe[tip.probeIdx] || usedGallery[tip.galleryIdx] {
			continue
		}
		usedProbe[tip.probeIdx] = true
		usedGallery[tip.galleryIdx] = true
		matchedScores = append(matchedScores, tip.score)
	}

	// Step 5: Overlap-Aware Global Score Accumulation
	var accumulatedScore float64
	if len(matchedScores) > 0 {
		var sum float64
		for _, s := range matchedScores {
			sum += s
		}

		// Denominator: bounded by min(probe, gallery) to remain robust against partial rotation crop
		denom := math.Min(float64(len(probe.Cylinders)), float64(len(gallery.Cylinders)))
		if denom > 0 {
			matchRatio := float64(len(matchedScores)) / denom
			avgSim := sum / float64(len(matchedScores))
			// Production biometrics: weighted combination of topological inlier coverage and local cylinder similarity
			accumulatedScore = (0.45*matchRatio + 0.55*avgSim) * 100.0
		}

		// Statistical significance check: penalize if template has ≥12 minutiae but matched inliers < 12
		if denom >= 12 && len(matchedScores) < 12 {
			accumulatedScore *= float64(len(matchedScores)) / 12.0
		}

		if accumulatedScore > 100.0 {
			accumulatedScore = 100.0
		}
	}

	duration := time.Since(startTime).Microseconds()
	isMatch := accumulatedScore >= m.GlobalScoreThreshold

	m.Logger.DebugContext(ctx, "mcc verification performed",
		slog.String("probe_id", probe.ID),
		slog.String("gallery_id", gallery.ID),
		slog.Float64("score", accumulatedScore),
		slog.Int("matched_pairs", len(matchedScores)),
		slog.Bool("is_match", isMatch),
		slog.Int64("duration_us", duration),
	)

	return MatchVerificationResult{
		IsMatch:          isMatch,
		Score:            accumulatedScore,
		MatchedPairs:     len(matchedScores),
		DurationMicrosec: duration,
	}, nil
}

// SerializeAll serializes all cylinders into a contiguous byte slice.
func (t *Template) SerializeAll() []byte {
	cylinderSize := 4 + 8 + (TotalWords * 8)
	buf := make([]byte, len(t.Cylinders)*cylinderSize)
	for i, c := range t.Cylinders {
		copy(buf[i*cylinderSize:(i+1)*cylinderSize], c.Serialize())
	}
	return buf
}

// DeserializeAll restores a slice of cylinders from bytes.
func DeserializeAll(data []byte) ([]Cylinder, error) {
	cylinderSize := 4 + 8 + (TotalWords * 8)
	if len(data)%cylinderSize != 0 {
		return nil, fmt.Errorf("invalid byte length for cylinders slice: %d", len(data))
	}
	count := len(data) / cylinderSize
	cyls := make([]Cylinder, count)
	for i := 0; i < count; i++ {
		c, err := Deserialize(data[i*cylinderSize : (i+1)*cylinderSize])
		if err != nil {
			return nil, err
		}
		cyls[i] = *c
	}
	return cyls, nil
}
