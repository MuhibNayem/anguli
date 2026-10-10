package minutiae

import (
	"math"
)

// Extractor handles minutiae extraction from a skeletonized binary matrix.
type Extractor struct {
	BorderMargin float64
	MinDistance  float64
}

// NewExtractor creates a new extractor instance with production defaults.
func NewExtractor() *Extractor {
	return &Extractor{
		BorderMargin: 8.0,
		MinDistance:  4.0,
	}
}

// Extract detects all endings and bifurcations using the Rutovitz Crossing Number algorithm.
func (e *Extractor) Extract(skeleton [][]uint8, width, height int, orientations [][]float64, blockSize int) []Minutia {
	var raw []Minutia
	margin := int(e.BorderMargin)

	for y := margin; y < height-margin; y++ {
		for x := margin; x < width-margin; x++ {
			if skeleton[y][x] != 1 {
				continue
			}

			// Neighbors in clockwise order starting from top
			p2 := skeleton[y-1][x]
			p3 := skeleton[y-1][x+1]
			p4 := skeleton[y][x+1]
			p5 := skeleton[y+1][x+1]
			p6 := skeleton[y+1][x]
			p7 := skeleton[y+1][x-1]
			p8 := skeleton[y][x-1]
			p9 := skeleton[y-1][x-1]

			neighbors := [9]uint8{p2, p3, p4, p5, p6, p7, p8, p9, p2}
			var sumDiff int
			for i := 0; i < 8; i++ {
				diff := int(neighbors[i]) - int(neighbors[i+1])
				if diff < 0 {
					diff = -diff
				}
				sumDiff += diff
			}
			cn := sumDiff / 2

			// Local orientation field fallback
			var flowAngle float64
			hasFlow := false
			if len(orientations) > 0 && blockSize > 0 {
				r := y / blockSize
				c := x / blockSize
				if r < len(orientations) && c < len(orientations[r]) {
					flowAngle = orientations[r][c]
					hasFlow = true
				}
			}

			switch cn {
			case 1:
				// Ridge ending: trace outward along the single ridge branch
				angle := traceSkeletonEnding(skeleton, x, y, width, height, 5)
				if hasFlow {
					angle = alignWithFlow(angle, flowAngle)
				}
				raw = append(raw, Minutia{
					X:       uint16(x),
					Y:       uint16(y),
					Angle:   angle,
					Type:    TypeEnding,
					Quality: 85,
				})
			case 3:
				// Ridge bifurcation: trace the three diverging branches
				angle := traceSkeletonBifurcation(skeleton, x, y, width, height, 5)
				if hasFlow {
					angle = alignWithFlow(angle, flowAngle)
				}
				raw = append(raw, Minutia{
					X:       uint16(x),
					Y:       uint16(y),
					Angle:   angle,
					Type:    TypeBifurcation,
					Quality: 90,
				})
			}
		}
	}

	return FilterSpuriousMinutiae(raw, e.MinDistance)
}

// traceSkeletonEnding traces outward along the skeleton ridge up to maxSteps pixels
func traceSkeletonEnding(skeleton [][]uint8, x, y, width, height, maxSteps int) float64 {
	currX, currY := x, y
	prevX, prevY := x, y

	for step := 0; step < maxSteps; step++ {
		foundNext := false
		for dy := -1; dy <= 1; dy++ {
			for dx := -1; dx <= 1; dx++ {
				if dx == 0 && dy == 0 {
					continue
				}
				nx := currX + dx
				ny := currY + dy
				if nx < 0 || nx >= width || ny < 0 || ny >= height {
					continue
				}
				if skeleton[ny][nx] == 1 && (nx != prevX || ny != prevY) {
					prevX, prevY = currX, currY
					currX, currY = nx, ny
					foundNext = true
					break
				}
			}
			if foundNext {
				break
			}
		}
		if !foundNext {
			break
		}
	}

	// Vector from ridge interior toward ending terminus (x, y)
	dx := float64(x - currX)
	dy := float64(y - currY)
	if dx == 0 && dy == 0 {
		return 0.0
	}
	a := math.Atan2(dy, dx)
	if a < 0 {
		a += 2 * math.Pi
	}
	return a
}

// traceSkeletonBifurcation traces each of the three branches to compute the trunk orientation
func traceSkeletonBifurcation(skeleton [][]uint8, x, y, width, height, maxSteps int) float64 {
	var branchVectors [][2]float64

	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			nx := x + dx
			ny := y + dy
			if nx < 0 || nx >= width || ny < 0 || ny >= height {
				continue
			}
			if skeleton[ny][nx] == 1 {
				currX, currY := nx, ny
				prevX, prevY := x, y
				for step := 1; step < maxSteps; step++ {
					foundNext := false
					for ddy := -1; ddy <= 1; ddy++ {
						for ddx := -1; ddx <= 1; ddx++ {
							if ddx == 0 && ddy == 0 {
								continue
							}
							nnx := currX + ddx
							nny := currY + ddy
							if nnx < 0 || nnx >= width || nny < 0 || nny >= height {
								continue
							}
							if skeleton[nny][nnx] == 1 && (nnx != prevX || nny != prevY) {
								prevX, prevY = currX, currY
								currX, currY = nnx, nny
								foundNext = true
								break
							}
						}
						if foundNext {
							break
						}
					}
					if !foundNext {
						break
					}
				}
				branchVectors = append(branchVectors, [2]float64{float64(currX - x), float64(currY - y)})
			}
		}
	}

	if len(branchVectors) == 0 {
		return 0.0
	}

	var sumX, sumY float64
	for _, v := range branchVectors {
		mag := math.Hypot(v[0], v[1])
		if mag > 0 {
			sumX += v[0] / mag
			sumY += v[1] / mag
		}
	}

	// Trunk points opposite to the net branch vector
	a := math.Atan2(-sumY, -sumX)
	if a < 0 {
		a += 2 * math.Pi
	}
	return a
}

// alignWithFlow aligns a directed candidate angle [0, 2π) with the undirected ridge flow [0, π)
func alignWithFlow(directedAngle, flowAngle float64) float64 {
	// Candidate 1: flowAngle, Candidate 2: flowAngle + π
	c1 := flowAngle
	c2 := flowAngle + math.Pi
	if c2 >= 2*math.Pi {
		c2 -= 2 * math.Pi
	}

	diff1 := math.Abs(directedAngle - c1)
	if diff1 > math.Pi {
		diff1 = 2*math.Pi - diff1
	}
	diff2 := math.Abs(directedAngle - c2)
	if diff2 > math.Pi {
		diff2 = 2*math.Pi - diff2
	}

	if diff1 <= diff2 {
		return c1
	}
	return c2
}

// FilterSpuriousMinutiae eliminates false minutiae pairs that are unrealistically close (e.g. broken bridges, spurs).
// Ensures deterministic, order-independent suppression.
func FilterSpuriousMinutiae(points []Minutia, minDistance float64) []Minutia {
	valid := make([]bool, len(points))
	for i := range valid {
		valid[i] = true
	}

	// Suppress all pairs whose mutual Euclidean distance is below the minDistance threshold
	for i := 0; i < len(points); i++ {
		for j := i + 1; j < len(points); j++ {
			dx := float64(points[i].X) - float64(points[j].X)
			dy := float64(points[i].Y) - float64(points[j].Y)
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist < minDistance {
				valid[i] = false
				valid[j] = false
			}
		}
	}

	filtered := make([]Minutia, 0, len(points))
	for i, ok := range valid {
		if ok {
			filtered = append(filtered, points[i])
		}
	}
	return filtered
}
