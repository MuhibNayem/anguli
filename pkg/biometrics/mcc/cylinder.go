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

// SimilarityWithShift evaluates cylinder similarity allowing directional slice shifts.
// Accommodates ±1 slice (±30°) orientation estimation jitter.
func (c *Cylinder) SimilarityWithShift(other *Cylinder, maxShift int) float64 {
	baseSim := c.Similarity(other)
	if maxShift <= 0 || baseSim >= 0.80 {
		return baseSim
	}

	bestSim := baseSim
	for shift := -maxShift; shift <= maxShift; shift++ {
		if shift == 0 {
			continue
		}
		var intersectionBits int
		var unionBits int

		for p := 0; p < SpatialGridSize; p++ {
			for q := 0; q < SpatialGridSize; q++ {
				for d := 0; d < DirectionSlices; d++ {
					dOther := (d + shift + DirectionSlices) % DirectionSlices
					idx1 := (p*SpatialGridSize+q)*DirectionSlices + d
					idx2 := (p*SpatialGridSize+q)*DirectionSlices + dOther

					b1 := (c.Bits[idx1/64] >> (idx1 % 64)) & 1
					b2 := (other.Bits[idx2/64] >> (idx2 % 64)) & 1

					if b1 == 1 && b2 == 1 {
						intersectionBits++
					}
					if b1 == 1 || b2 == 1 {
						unionBits++
					}
				}
			}
		}

		if unionBits > 0 {
			sim := float64(intersectionBits) / float64(unionBits)
			if sim > bestSim {
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
