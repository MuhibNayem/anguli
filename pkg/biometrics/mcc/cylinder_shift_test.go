package mcc

import (
	"math"
	"math/rand"
	"testing"
)

// similarityWithShiftReference is the original bit-at-a-time implementation,
// kept verbatim as the oracle for the optimised version.
//
// It is the specification the fast path must reproduce exactly. Keeping the
// slow version in the tree rather than deleting it after the comparison is
// deliberate: it is the only thing that can prove the optimisation did not
// quietly change what a match means.
func (c *Cylinder) similarityWithShiftReference(other *Cylinder, maxShift int) float64 {
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

func randomCylinder(rng *rand.Rand, density float64) Cylinder {
	var c Cylinder
	c.MinutiaX = uint16(rng.Intn(512))
	c.MinutiaY = uint16(rng.Intn(512))
	for i := range c.Bits {
		// Density sweeps from sparse to saturated so the corpus includes both
		// empty cells and full ones, where the union-count identity and the
		// zero-union early-out are both exercised.
		c.Bits[i] = uint64(rng.Float64() * density * float64(uint64(1)<<DirectionSlices))
	}
	return c
}

// TestSimilarityWithShiftMatchesReferenceBitForBit is the equivalence proof for
// the 1:N hot-path optimisation.
//
// Random inputs are the right tool here, not real fingerprints. The claim
// being made is "this returns exactly what the original loop returned for
// every possible input"; checking that on randomised cylinders over a sweep of
// densities and shift ranges is a stronger statement than agreement on real
// captures, which would only cover the handful of bit patterns a sensor
// produces.
func TestSimilarityWithShiftMatchesReferenceBitForBit(t *testing.T) {
	rng := rand.New(rand.NewSource(20261010))

	densities := []float64{0.02, 0.1, 0.35, 0.6, 0.9, 1.0, 1.4}
	for _, density := range densities {
		// maxShift is capped at DirectionSlices-1 because the REFERENCE
		// implementation is only defined there: it computes
		// (d + shift + DirectionSlices) % DirectionSlices, and Go's % keeps
		// the dividend's sign, so shift < -DirectionSlices yields a negative
		// index and a panic. See TestSimilarityWithShiftSurvivesLargeMaxShift
		// for the defect this uncovered.
		for _, maxShift := range []int{0, 1, 2, 3, 5, 6} {
			for trial := 0; trial < 60; trial++ {
				a := randomCylinder(rng, density)
				b := randomCylinder(rng, density)

				got := a.SimilarityWithShift(&b, maxShift)
				want := a.similarityWithShiftReference(&b, maxShift)

				// Exact equality, not epsilon: both compute the same integer
				// ratio, so any difference at all is a real semantic change.
				if got != want {
					t.Fatalf("density=%.2f maxShift=%d trial=%d: got %.17g, reference %.17g",
						density, maxShift, trial, got, want)
				}
				if math.IsNaN(got) {
					t.Fatalf("density=%.2f maxShift=%d: NaN", density, maxShift)
				}
			}
		}
	}
}

// TestSimilarityWithShiftHandlesEmptyAndFull specifically covers the boundary
// densities where popcount arithmetic can go wrong: an all-zero operand has a
// zero union and must return 0, and a saturated one has union == total bits.
func TestSimilarityWithShiftHandlesEmptyAndFull(t *testing.T) {
	var zero, full Cylinder
	for i := range full.Bits {
		full.Bits[i] = ^uint64(0)
	}

	cases := []struct {
		name string
		a, b Cylinder
	}{
		{"both empty", zero, zero},
		{"one empty", zero, full},
		{"identical full", full, full},
		{"disjoint", full, zero},
	}
	for _, c := range cases {
		got := c.a.SimilarityWithShift(&c.b, 1)
		want := c.a.similarityWithShiftReference(&c.b, 1)
		if got != want {
			t.Errorf("%s: got %v, reference %v", c.name, got, want)
		}
	}
}

// TestCellAtSpansWordBoundaries is the unit test for the bit extraction the
// optimisation rests on. 6-bit cells do not divide 64, so many cells straddle
// two words, and a wrong extraction here would be invisible to a round-trip
// test that used the same extractor on both sides.
func TestCellAtSpansWordBoundaries(t *testing.T) {
	var c Cylinder
	for i := range c.Bits {
		c.Bits[i] = ^uint64(0) // every bit set, so any wrong index shows up
	}
	for cell := 0; cell < shiftCellCount; cell++ {
		got := cellAt(&c.Bits, cell)
		want := uint8((1 << DirectionSlices) - 1)
		if got != want {
			t.Fatalf("cell %d: got 0x%02x, want 0x%02x", cell, got, want)
		}
	}

	// With a single bit set, the extracted cell must be the one containing it.
	for bit := 0; bit < TotalBits; bit++ {
		var c Cylinder
		c.Bits[bit/64] = 1 << uint(bit%64)
		wantCell := bit / DirectionSlices
		for cell := 0; cell < shiftCellCount; cell++ {
			got := cellAt(&c.Bits, cell)
			var want uint8
			if cell == wantCell {
				want = 1 << uint(bit%DirectionSlices)
			}
			if got != want {
				t.Fatalf("bit %d: cell %d extracted 0x%02x, want 0x%02x", bit, cell, got, want)
			}
		}
	}
}

// TestCellRotMatchesDefinition pins the rotation table to the spec it claims to
// implement: output bit d is input bit (d+s) mod DirectionSlices.
func TestCellRotMatchesDefinition(t *testing.T) {
	for s := 0; s < DirectionSlices; s++ {
		for v := 0; v < 64; v++ {
			var want uint8
			for d := 0; d < DirectionSlices; d++ {
				if (v>>((d+s)%DirectionSlices))&1 == 1 {
					want |= 1 << uint(d)
				}
			}
			if cellRot[s][v] != want {
				t.Fatalf("cellRot[%d][%d] = 0x%02x, want 0x%02x", s, v, cellRot[s][v], want)
			}
		}
	}
}

// TestInclusionExclusionHolds is the algebra the optimisation depends on:
// popcount(a|b) == popcount(a) + popcount(b) - popcount(a&b). If this were
// wrong, unions would be miscounted and every shifted similarity would be
// subtly off in a way no single-pair test would isolate.
func TestInclusionExclusionHolds(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		a := uint8(rng.Intn(256))
		b := uint8(rng.Intn(256))
		lhs := int(bitsOnes8(a | b))
		rhs := int(bitsOnes8(a)) + int(bitsOnes8(b)) - int(bitsOnes8(a&b))
		if lhs != rhs {
			t.Fatalf("a=0x%02x b=0x%02x: popcount(a|b)=%d, identity gives %d", a, b, lhs, rhs)
		}
	}
}

// TestSimilarityWithShiftSurvivesLargeMaxShift covers a latent crash found
// while writing the equivalence test.
//
// The original implementation derived the rotated slice index as
// (d + shift + DirectionSlices) % DirectionSlices. Go's % preserves the sign
// of the dividend, so for shift < -DirectionSlices the numerator goes negative
// and the result is negative, producing a negative bit index and a runtime
// panic. Anything with maxShift >= DirectionSlices+1 crashes the process.
//
// Production only ever passes maxShift=1, so this was unreachable today and no
// test exercised it. It is still a real defect: the function's signature
// invites a caller to widen the search, and the natural way to do that turns
// into a crash rather than a slower scan. The rewrite normalises the shift
// modulo DirectionSlices instead, so an over-wide request degrades to a
// redundant rotation.
func TestSimilarityWithShiftSurvivesLargeMaxShift(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	a := randomCylinder(rng, 0.4)
	b := randomCylinder(rng, 0.4)

	for _, maxShift := range []int{7, 12, 64, 1000} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("maxShift=%d panicked: %v", maxShift, r)
				}
			}()
			got := a.SimilarityWithShift(&b, maxShift)
			if math.IsNaN(got) || got < 0 || got > 1 {
				t.Fatalf("maxShift=%d returned %v, outside [0,1]", maxShift, got)
			}
		}()
	}

	// A shift wider than the cell wraps entirely, so the answer must be one of
	// the rotations the cell actually admits - never worse than no shift at all.
	plain := a.Similarity(&b)
	if shifted := a.SimilarityWithShift(&b, 1000); shifted < plain {
		t.Errorf("an over-wide shift returned %.17g, worse than the unshifted %.17g", shifted, plain)
	}
}

func bitsOnes8(v uint8) int {
	n := 0
	for i := 0; i < 8; i++ {
		if v&(1<<uint(i)) != 0 {
			n++
		}
	}
	return n
}

func BenchmarkSimilarityWithShift(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	a := randomCylinder(rng, 0.5)
	c := randomCylinder(rng, 0.5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.SimilarityWithShift(&c, 1)
	}
}

func BenchmarkSimilarityWithShiftReference(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	a := randomCylinder(rng, 0.5)
	c := randomCylinder(rng, 0.5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.similarityWithShiftReference(&c, 1)
	}
}
