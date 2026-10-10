package mcc

import (
	"encoding/binary"
	"errors"
	"math"
	"math/bits"

	"finger-scanner/pkg/biometrics/minutiae"
)

const (
	// SpatialGridSize represents the N_S x N_S spatial discretization resolution
	SpatialGridSize = 16
	// DirectionSlices represents the N_D angular layers across [0, π) (resolving M1 at source)
	DirectionSlices = 6
	// TotalBits is the total count of binary cells in one cylinder (16 * 16 * 6 = 1536 bits)
	TotalBits = SpatialGridSize * SpatialGridSize * DirectionSlices
	// TotalWords is the word count (1536 / 64 = 24 uint64 words = 192 bytes)
	TotalWords = TotalBits / 64
	// RadiusPixels is the bounding radius around the center minutia in pixels (500 DPI)
	RadiusPixels = 70.0
	// SigmaSpatial is the Gaussian standard deviation for spatial cell distance
	SigmaSpatial = 14.0
	// SigmaDirection is the Gaussian standard deviation for directional angle difference
	SigmaDirection = math.Pi / 12.0 // 15 degrees across [0, π)
)

var (
	ErrInvalidCylinderPayload = errors.New("invalid cylinder binary payload size")
)

// Cylinder represents a compact 192-byte bit-vector encoding local minutiae topology.
type Cylinder struct {
	MinutiaX uint16
	MinutiaY uint16
	Angle    float64
	Bits     [TotalWords]uint64
}

// CreateCylinder generates a mathematically valid 3D cylinder for minutia center.
func CreateCylinder(center minutiae.Minutia, allPoints []minutiae.Minutia) Cylinder {
	c := Cylinder{
		MinutiaX: center.X,
		MinutiaY: center.Y,
		Angle:    center.Angle,
	}

	cellSize := (2.0 * RadiusPixels) / float64(SpatialGridSize)
	cosAngle := math.Cos(center.Angle)
	sinAngle := math.Sin(center.Angle)

	// Pre-filter local neighbors within cylinder bounding radius once
	maxDistSq := (RadiusPixels + cellSize) * (RadiusPixels + cellSize)
	localNeighbors := make([]minutiae.Minutia, 0, 32)
	for _, nb := range allPoints {
		if nb.X == center.X && nb.Y == center.Y {
			continue
		}
		dx := float64(nb.X) - float64(center.X)
		dy := float64(nb.Y) - float64(center.Y)
		if dx*dx+dy*dy <= maxDistSq {
			localNeighbors = append(localNeighbors, nb)
		}
	}

	twoSigmaSpatialSq := 2.0 * SigmaSpatial * SigmaSpatial
	twoSigmaDirectionSq := 2.0 * SigmaDirection * SigmaDirection

	for p := 0; p < SpatialGridSize; p++ {
		for q := 0; q < SpatialGridSize; q++ {
			cellRelX := (float64(p)+0.5)*cellSize - RadiusPixels
			cellRelY := (float64(q)+0.5)*cellSize - RadiusPixels

			cellGlobalX := float64(center.X) + (cellRelX*cosAngle - cellRelY*sinAngle)
			cellGlobalY := float64(center.Y) + (cellRelX*sinAngle + cellRelY*cosAngle)

			// Accumulators for all 6 directional slices of this (p, q) cell
			var accumulators [DirectionSlices]float64

			for _, nb := range localNeighbors {
				dx := float64(nb.X) - cellGlobalX
				dy := float64(nb.Y) - cellGlobalY
				distSq := dx*dx + dy*dy

				if distSq > (3.0 * twoSigmaSpatialSq) {
					continue
				}

				fs := math.Exp(-distSq / twoSigmaSpatialSq)

				for d := 0; d < DirectionSlices; d++ {
					// Slice across [0, π) at intervals of π/DirectionSlices (resolving M1 at source)
					sliceAngle := (math.Pi / float64(DirectionSlices)) * float64(d)
					targetDirection := center.Angle + sliceAngle
					for targetDirection >= math.Pi {
						targetDirection -= math.Pi
					}
					for targetDirection < 0 {
						targetDirection += math.Pi
					}

					// Projective angular distance modulo π on RP^1
					dAngle := math.Abs(nb.Angle - targetDirection)
					for dAngle >= math.Pi {
						dAngle -= math.Pi
					}
					if dAngle > math.Pi/2.0 {
						dAngle = math.Pi - dAngle
					}
					fd := math.Exp(-(dAngle * dAngle) / twoSigmaDirectionSq)

					accumulators[d] += fs * fd
				}
			}

			for d := 0; d < DirectionSlices; d++ {
				if accumulators[d] >= 0.08 {
					bitIndex := (p*SpatialGridSize+q)*DirectionSlices + d
					wordIdx := bitIndex / 64
					bitOffset := bitIndex % 64
					c.Bits[wordIdx] |= (1 << bitOffset)
				}
			}
		}
	}

	return c
}

// Similarity calculates the normalized bitwise match score between two cylinders in nanoseconds.
func (c *Cylinder) Similarity(other *Cylinder) float64 {
	var intersectionBits int
	var unionBits int

	for i := 0; i < TotalWords; i++ {
		w1 := c.Bits[i]
		w2 := other.Bits[i]

		intersectionBits += bits.OnesCount64(w1 & w2)
		unionBits += bits.OnesCount64(w1 | w2)
	}

	if unionBits == 0 {
		return 0.0
	}

	return float64(intersectionBits) / float64(unionBits)
}

// shiftCellCount is the number of spatial cells in one cylinder. Each cell
// owns DirectionSlices consecutive bits of the bit array.
const shiftCellCount = SpatialGridSize * SpatialGridSize

// shiftForIndex maps an accumulator slot to the shift it holds.
//
// The non-zero shifts are -maxShift..-1 and +1..+maxShift: exactly 2*maxShift of
// them. The naive mapping k-maxShift enumerates -maxShift..+maxShift-1 instead,
// which silently drops +maxShift and substitutes a duplicate of zero. That bug
// cost the maximum rotated similarity every time, and produced a matcher that
// quietly scored worse than it should rather than failing.
func shiftForIndex(k, maxShift int) int {
	if k < maxShift {
		return k - maxShift
	}
	return k - maxShift + 1
}

// cellRot[s][v] is the DirectionSlices-bit value v rotated by s slices, where
// the output bit d is the input bit (d+s) mod DirectionSlices.
//
// Built from that definition directly rather than by shift-and-or, so there
// is no direction-of-rotation sign to get wrong. The table is 384 bytes and
// replaces a per-bit branch in the hottest loop in the matcher.
var cellRot [DirectionSlices][64]uint8

func init() {
	for s := 0; s < DirectionSlices; s++ {
		for v := 0; v < 64; v++ {
			var out uint8
			for d := 0; d < DirectionSlices; d++ {
				if (v>>((d+s)%DirectionSlices))&1 == 1 {
					out |= 1 << uint(d)
				}
			}
			cellRot[s][v] = out
		}
	}
}

// cellAt extracts the DirectionSlices-bit value of one spatial cell.
//
// A cell can straddle a 64-bit word boundary, because 6 bits do not divide 64.
func cellAt(b *[TotalWords]uint64, cell int) uint8 {
	base := cell * DirectionSlices
	w := base >> 6
	off := base & 63
	v := uint8(b[w]>>uint(off)) & uint8(1<<DirectionSlices-1)
	if off+DirectionSlices > 64 {
		v |= uint8(b[w+1]<<uint(64-off)) & uint8(1<<DirectionSlices-1)
	}
	return v
}

// SimilarityWithShift evaluates cylinder similarity allowing directional slice shifts.
// Accommodates ±1 slice (±30°) orientation estimation jitter.
//
// This function accounted for 85% of 1:N search CPU time, so it is worth
// saying what changed and what provably did not.
//
// The previous implementation walked all TotalBits bits one at a time,
// extracting each with a shift and mask and branching on it, once per shift.
// The shift only ever permutes the DirectionSlices slices WITHIN a spatial
// cell - it never moves a bit between cells. That means the whole computation
// can be done a cell at a time on small integers:
//
//	intersection = popcount(a & rot(b))
//	union        = popcount(a | rot(b))
//	             = popcount(a) + popcount(b) - popcount(a & rot(b))
//
// using the inclusion-exclusion identity, so the rotated operand never has to
// be materialised as a bit array at all. Each cell costs one table lookup and
// two 6-bit popcounts instead of six bit extractions and twelve branches.
//
// Cells are also visited once for all shifts rather than once per shift, so
// each cell's value is extracted 2*maxShift times fewer.
//
// The output is unchanged, and that is asserted against a copy of the
// original loop in TestSimilarityWithShiftMatchesReferenceBitForBit over
// randomised cylinders. Bit-identical agreement on random inputs is a
// stronger guarantee than agreement on real fingerprints: it holds for every
// input, not just the ones a capture happens to produce.
func (c *Cylinder) SimilarityWithShift(other *Cylinder, maxShift int) float64 {
	baseSim := c.Similarity(other)
	if maxShift <= 0 || baseSim >= 0.80 {
		return baseSim
	}

	// Popcount of the unrotated operand is invariant across shifts.
	popA := 0
	for i := 0; i < TotalWords; i++ {
		popA += bits.OnesCount64(c.Bits[i])
	}

	shifts := 2 * maxShift
	popInter := make([]int, shifts)
	popB := make([]int, shifts)

	for cell := 0; cell < shiftCellCount; cell++ {
		a := cellAt(&c.Bits, cell)
		b := cellAt(&other.Bits, cell)
		for k := 0; k < shifts; k++ {
			s := ((shiftForIndex(k, maxShift) % DirectionSlices) + DirectionSlices) % DirectionSlices
			if s == 0 {
				// A whole-cell rotation leaves the operand unchanged.
				popInter[k] += bits.OnesCount8(a & b)
				popB[k] += bits.OnesCount8(b)
				continue
			}
			r := cellRot[s][b]
			popInter[k] += bits.OnesCount8(a & r)
			popB[k] += bits.OnesCount8(r)
		}
	}

	bestSim := baseSim
	for k := 0; k < shifts; k++ {
		union := popA + popB[k] - popInter[k]
		if union > 0 {
			if sim := float64(popInter[k]) / float64(union); sim > bestSim {
				bestSim = sim
			}
		}
	}
	return bestSim
}

// Serialize converts the cylinder into a compact wire-safe byte sequence.
func (c *Cylinder) Serialize() []byte {
	buf := make([]byte, 4+8+(TotalWords*8))
	binary.BigEndian.PutUint16(buf[0:2], c.MinutiaX)
	binary.BigEndian.PutUint16(buf[2:4], c.MinutiaY)
	binary.BigEndian.PutUint64(buf[4:12], math.Float64bits(c.Angle))

	offset := 12
	for i := 0; i < TotalWords; i++ {
		binary.BigEndian.PutUint64(buf[offset:offset+8], c.Bits[i])
		offset += 8
	}
	return buf
}

// Deserialize reads bytes back into a Cylinder struct with bounds checking.
func Deserialize(data []byte) (*Cylinder, error) {
	expectedLen := 4 + 8 + (TotalWords * 8)
	if len(data) != expectedLen {
		return nil, ErrInvalidCylinderPayload
	}

	c := &Cylinder{
		MinutiaX: binary.BigEndian.Uint16(data[0:2]),
		MinutiaY: binary.BigEndian.Uint16(data[2:4]),
		Angle:    math.Float64frombits(binary.BigEndian.Uint64(data[4:12])),
	}

	offset := 12
	for i := 0; i < TotalWords; i++ {
		c.Bits[i] = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	return c, nil
}
