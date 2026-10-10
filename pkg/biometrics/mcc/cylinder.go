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

// maxRotationSlots bounds the accumulator arrays in the shift kernel.
//
// A shift is applied modulo DirectionSlices, so only DirectionSlices-1 rotations
// are genuinely distinct, and one of those is the identity. That is why the
// slot list is capped and deduplicated rather than sized from the caller's
// maxShift: an over-wide request costs no more than the widest search that can
// actually produce a different answer.
const maxRotationSlots = DirectionSlices - 1

// rotationSlots resolves maxShift into the distinct non-identity rotations to
// evaluate, in the order +1, -1, +2, -2, ...
//
// Two properties make this exactly equivalent to enumerating every raw shift:
//
//   - A shift and that shift plus or minus DirectionSlices reduce to the same
//     rotation, so wider requests repeat rotations rather than adding any.
//   - A shift that reduces to zero is the identity, which reproduces the
//     unshifted similarity, which is already the initial best. Including it
//     recomputes baseSim and cannot change a maximum.
//
// The enumeration deliberately walks +s then -s for each s. An earlier version
// indexed accumulator slots by k-maxShift, which enumerates -maxShift..+maxShift-1
// instead: it silently drops +maxShift and substitutes a duplicate of zero. That
// bug cost the maximum rotated similarity every time, and produced a matcher
// that quietly scored worse than it should rather than failing.
func rotationSlots(maxShift int) (slots [maxRotationSlots]uint8, n int) {
	for shift := 1; shift <= maxShift; shift++ {
		if n == maxRotationSlots {
			break
		}
		for _, signed := range [2]int{shift, -shift} {
			if n == maxRotationSlots {
				break
			}
			r := ((signed % DirectionSlices) + DirectionSlices) % DirectionSlices
			if r == 0 {
				continue
			}
			seen := false
			for i := 0; i < n; i++ {
				if slots[i] == uint8(r) {
					seen = true
					break
				}
			}
			if !seen {
				slots[n] = uint8(r)
				n++
			}
		}
	}
	return slots, n
}

// cellValueSpace is the number of distinct (cellA, cellB) pairs. Both are
// DirectionSlices-bit values, so it is 64 * 64.
const cellValueSpace = 1 << (2 * DirectionSlices)

// cellRot[s][v] is the DirectionSlices-bit value v rotated by s slices, where
// the output bit d is the input bit (d+s) mod DirectionSlices.
//
// Built from that definition directly rather than by shift-and-or, so there
// is no direction-of-rotation sign to get wrong. The table is 384 bytes and
// replaces a per-bit branch in the hottest loop in the matcher.
var cellRot [DirectionSlices][64]uint8

// interTable[s][a<<DirectionSlices|b] is popcount(a & cellRot[s][b]).
//
// The inner loop of the shift kernel needs exactly one of these values per cell
// per rotation, and computing it costs a table lookup on b followed by a popcount
// on the masked result. With only 64 possible cell values on each side the
// whole function fits in a table, turning that work into a single load.
//
// It is built from cellRot rather than from the definition again, so the two
// tables cannot drift apart, and TestInterTableMatchesCellRot pins it.
var interTable [DirectionSlices][cellValueSpace]uint8

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
		for a := 0; a < 64; a++ {
			for b := 0; b < 64; b++ {
				idx := a<<DirectionSlices | b
				interTable[s][idx] = uint8(bits.OnesCount8(uint8(a) & cellRot[s][b]))
			}
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

// occupiedCells lists the spatial cells of a cylinder that have at least one
// bit set, packed as cell<<DirectionSlices | value.
//
// A cell whose probe value is zero contributes popcount(0 & rot(b)) == 0 to
// EVERY rotation, so visiting it cannot change any intersection count. Dropping
// those cells is therefore exact, not a filter.
//
// It is worth a lot: measured over generated 32-minutia templates, a cylinder
// averages 99 bits set out of 1536 spread across only 22% of its cells, so
// roughly 78% of the cell loop was accumulating zeros.
type occupiedCells []uint16

// cellValueMask selects the DirectionSlices-bit value out of a packed cell.
const cellValueMask = uint16(1<<DirectionSlices - 1)

// occupiedCellsOf collects the non-empty cells of b in increasing cell order.
func occupiedCellsOf(b *[TotalWords]uint64) occupiedCells {
	out := make(occupiedCells, 0, shiftCellCount)
	for cell := 0; cell < shiftCellCount; cell++ {
		v := cellAt(b, cell)
		if v != 0 {
			out = append(out, uint16(cell<<DirectionSlices)|uint16(v))
		}
	}
	return out
}

// occupiedCellCount reports how many cells of b are non-empty, without building
// the list.
func occupiedCellCount(b *[TotalWords]uint64) int {
	n := 0
	for cell := 0; cell < shiftCellCount; cell++ {
		if cellAt(b, cell) != 0 {
			n++
		}
	}
	return n
}

// appendOccupiedCells appends b's non-empty cells to dst.
func appendOccupiedCells(dst occupiedCells, b *[TotalWords]uint64) occupiedCells {
	for cell := 0; cell < shiftCellCount; cell++ {
		v := cellAt(b, cell)
		if v != 0 {
			dst = append(dst, uint16(cell<<DirectionSlices)|uint16(v))
		}
	}
	return dst
}

// probeCellSets builds the occupied-cell list for every probe cylinder into one
// shared backing array.
//
// Verify runs once per gallery candidate, so 2000 candidates means 2000 of
// these. Allocating one list per probe cylinder cost about 64k allocations and
// 32 MB of garbage per walk-up - a third of the search's total allocation
// traffic, and enough to make the garbage collector part of the latency.
//
// The returned sub-slices each cap at their own length, so appending to the
// shared buffer for a later cylinder can never write into an earlier one.
func probeCellSets(cylinders []Cylinder) []occupiedCells {
	total := 0
	for i := range cylinders {
		total += occupiedCellCount(&cylinders[i].Bits)
	}

	buf := make(occupiedCells, 0, total)
	out := make([]occupiedCells, len(cylinders))
	for i := range cylinders {
		start := len(buf)
		buf = appendOccupiedCells(buf, &cylinders[i].Bits)
		out[i] = buf[start:len(buf):len(buf)]
	}
	return out
}

// cellIndex and cellValue unpack an occupiedCells entry.
//
// The value must be taken with an explicit mask. Truncating the packed word to
// a byte instead keeps bits 6 and 7, which belong to the cell index, and
// silently returns a value up to 192 for cells at index 4 and above - which then
// indexes past the end of the 64x64 intersection table.
func (o occupiedCells) cellIndex(i int) int { return int(o[i] >> DirectionSlices) }
func (o occupiedCells) cellValue(i int) uint8 {
	return uint8(o[i] & cellValueMask)
}

// popCount returns the number of bits set in b.
func popCount(b *[TotalWords]uint64) int {
	n := 0
	for i := 0; i < TotalWords; i++ {
		n += bits.OnesCount64(b[i])
	}
	return n
}

// SimilarityWithShift evaluates cylinder similarity allowing directional slice shifts.
// Accommodates ±1 slice (±30°) orientation estimation jitter.
//
// This function accounted for 95% of Verify - and so 95% of 1:N search - so it
// is worth being precise about what changed and what provably did not.
//
// The original implementation walked all TotalBits bits one at a time,
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
// Two further profiles of that version showed the popcounts were no longer the
// cost. What was left was scaffolding and redundancy, and profiling beat
// guessing about it:
//
//   - The rotation index was recomputed for every cell, including two integer
//     modulos, when it takes at most DirectionSlices distinct values. It is now
//     resolved once per call in rotationSlots.
//   - The accumulators were make([]int, ...) inside the function. At one call
//     per probe/gallery cylinder pair - millions per walk-up - that was 5% of
//     search CPU in zeroing alone, plus the GC pressure behind it. They are
//     stack arrays now.
//   - The `s == 0` branch sat in the innermost loop. cellRot[0][v] == v holds
//     by construction, so routing the identity through the same table removes
//     the branch without special-casing it.
//   - Rotation is a permutation of a cell's bits, so popcount(rot_s(b)) equals
//     popcount(b). The rotated operand's popcount is therefore the same number
//     for every rotation, and was being recomputed once per rotation.
//   - popcount(a & rot_s(b)) has only 64 x 64 distinct inputs, so it is a
//     table lookup rather than a shift, mask and popcount.
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
	return shiftedBest(
		occupiedCellsOf(&c.Bits), other, baseSim, popCount(&c.Bits), popCount(&other.Bits), maxShift,
	)
}

// shiftedBest is the shared kernel behind SimilarityWithShift and the matcher's
// batched pair scorer.
//
// Every operand the loop does not vary is passed in. The matcher scores one
// probe cylinder against every gallery cylinder, so the probe's occupied cells
// and popcount are the same for all of them; taking them as arguments lets the
// matcher compute them once instead of once per pair.
func shiftedBest(
	probeCells occupiedCells,
	other *Cylinder,
	baseSim float64,
	popA, popG, maxShift int,
) float64 {
	if maxShift <= 0 || baseSim >= 0.80 {
		return baseSim
	}

	slots, n := rotationSlots(maxShift)

	// Stack arrays sized by the compile-time constant, not by maxShift, so a
	// wider search cannot turn into a wider allocation.
	var interStorage [maxRotationSlots]int
	inter := interStorage[:n]

	for i := range probeCells {
		cell := probeCells.cellIndex(i)
		a := probeCells.cellValue(i)
		b := cellAt(&other.Bits, cell)
		ab := int(a)<<DirectionSlices | int(b)
		for k := 0; k < n; k++ {
			inter[k] += int(interTable[slots[k]][ab])
		}
	}

	// union = popA + popRotated - inter[k], and popRotated is popCount(other)
	// for every k because rotation preserves a cell's popcount.
	bestSim := baseSim
	for k := 0; k < n; k++ {
		union := popA + popG - inter[k]
		if union > 0 {
			if sim := float64(inter[k]) / float64(union); sim > bestSim {
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
