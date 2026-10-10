package iso19794b

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"testing"
)

// halfLSB is the largest orientation error a round trip can introduce. The
// angle field is one byte covering a full turn, so one LSB is 2*pi/256 and
// rounding to the nearest gives at most half of that.
var halfLSB = math.Pi / 256

// sample builds a realistic minutiae set with varied coordinates and types.
func sample(n int) []MinutiaFormat {
	r := rand.New(rand.NewSource(9))
	out := make([]MinutiaFormat, 0, n)
	for i := 0; i < n; i++ {
		typ := uint8(1)
		if i%3 == 0 {
			typ = 2
		}
		out = append(out, MinutiaFormat{
			Type:        typ,
			X:           uint16(r.Intn(maxCoord + 1)),
			Y:           uint16(r.Intn(maxCoord + 1)),
			Quality:     uint8(r.Intn(256)),
			Orientation: r.Float64() * 2 * math.Pi,
		})
	}
	return out
}

// TestMinutiaRecordMatchesTheStandard pins the six-byte record layout to the
// standard's own normative statements, offset by offset. This is the test that
// matters most in the package: a layout bug here produces records that parse
// cleanly and match nothing.
//
// The standard specifies, in terms:
//   - x occupies the lower fourteen bits of the first two bytes
//   - y occupies the lower fourteen bits of the third and fourth byte
//   - '01' is a ridge ending, '10' a bifurcation (2-bit type)
//   - the angle is 1.40625 (360/256) degrees per least significant bit
func TestMinutiaRecordMatchesTheStandard(t *testing.T) {
	// Angle 0 rad = 0 degrees = LSB 0.
	// Angle pi/2 rad = 90 degrees = LSB 64, since 90/1.40625 = 64 exactly.
	cases := []struct {
		name              string
		m                 MinutiaFormat
		firstTwo, nextTwo uint16 // the two 16-bit words, fully specified
		angle             uint8
		quality           uint8
	}{
		{
			// '01' in the top two bits; both coordinates zero.
			name:     "ridge ending at origin",
			m:        MinutiaFormat{Type: 1, X: 0, Y: 0, Quality: 0, Orientation: 0},
			firstTwo: 0x4000,
			nextTwo:  0x0000,
			angle:    0,
			quality:  0,
		},
		{
			// '10' in the top two bits, x and y both at the 14-bit maximum,
			// with the two reserved bits above y left at zero.
			name:     "bifurcation, max x and y",
			m:        MinutiaFormat{Type: 2, X: maxCoord, Y: maxCoord, Quality: 255, Orientation: 0},
			firstTwo: 0x8000 | maxCoord,
			nextTwo:  0x0000 | maxCoord,
			angle:    0,
			quality:  255,
		},
		{
			name:     "quarter turn angle",
			m:        MinutiaFormat{Type: 1, X: 1234, Y: 5678, Quality: 200, Orientation: math.Pi / 2},
			firstTwo: 0x4000 | 1234,
			nextTwo:  0x0000 | 5678,
			angle:    64, // 90 degrees / 1.40625
			quality:  200,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := Build(64, 64, 0, []MinutiaFormat{c.m})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			m := raw[RecordHeaderLen+fixedBlockLen:][:minutiaSize]

			if got := binary.BigEndian.Uint16(m[0:2]); got != c.firstTwo {
				t.Errorf("bytes [0:2] = 0x%04X; want 0x%04X", got, c.firstTwo)
			}
			if got := binary.BigEndian.Uint16(m[2:4]); got != c.nextTwo {
				t.Errorf("bytes [2:4] = 0x%04X; want 0x%04X (reserved bits must be zero)", got, c.nextTwo)
			}
			if m[4] != c.angle {
				t.Errorf("angle byte = %d; want %d", m[4], c.angle)
			}
			if m[5] != c.quality {
				t.Errorf("quality byte = %d; want %d", m[5], c.quality)
			}
			if len(m) != 6 {
				t.Errorf("minutia record is %d bytes; the 2005 format fixes it at 6", len(m))
			}
		})
	}
}

// TestAngleIs360Over256 asserts the granularity the standard names, expressed
// the other way round: a full turn must land on exactly 256 steps.
func TestAngleIs360Over256(t *testing.T) {
	if deg := angleUnits * 180 / math.Pi; math.Abs(deg-1.40625) > 1e-12 {
		t.Fatalf("one LSB is %v degrees; the standard specifies 1.40625", deg)
	}
}

// angleDelta is the smallest rotation between two angles, in radians.
func angleDelta(a, b float64) float64 {
	const twoPi = 2 * math.Pi
	d := math.Mod(math.Abs(math.Mod(a-b, twoPi)), twoPi)
	if d > math.Pi {
		d = twoPi - d
	}
	return d
}

// TestRoundTrip_MinutiaeSurviveExactly is the core property for template
// interop: a template exported must come back with the same minutiae, or a
// database round trip silently degrades every enrolled finger.
func TestRoundTrip_MinutiaeSurviveExactly(t *testing.T) {
	for _, n := range []int{0, 1, 2, 12, 40, 120, 256} {
		in := sample(n)
		raw, err := Build(200, 200, 0x01, in)
		if err != nil {
			t.Fatalf("Build(%d minutiae): %v", n, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%d minutiae): %v", n, err)
		}
		if len(got.Minutiae) != len(in) {
			t.Fatalf("got %d minutiae; want %d", len(got.Minutiae), len(in))
		}
		for i := range in {
			g := got.Minutiae[i]
			w := in[i]
			if g.Type != w.Type || g.X != w.X || g.Y != w.Y || g.Quality != w.Quality {
				t.Fatalf("minutia %d: got %+v; want %+v", i, g, w)
			}
			// The angle field is 8-bit, so it is lossy by design. The error
			// must stay within half an LSB.
			if delta := angleDelta(g.Orientation, w.Orientation); delta > halfLSB+1e-12 {
				t.Errorf("minutia %d orientation drifted by %v (half LSB is %v; got %v want %v)",
					i, delta, halfLSB, g.Orientation, w.Orientation)
			}
		}
		if got.Width != 200 || got.Height != 200 {
			t.Errorf("dimensions = %dx%d; want 200x200", got.Width, got.Height)
		}
		if got.FingerPosition != 0x01 {
			t.Errorf("FingerPosition = %d; want 1", got.FingerPosition)
		}
	}
}

// TestXAndYAreIndependentFields guards against X and Y being packed into one
// field: a single 12-bit pair silently mis-places every coordinate, and the
// round trip still succeeds.
func TestXAndYAreIndependentFields(t *testing.T) {
	cases := []struct{ x, y uint16 }{
		{0, 0},
		{maxCoord, 0}, // max X, zero Y
		{0, maxCoord}, // zero X, max Y - the case a packed field destroys
		{1, maxCoord},
		{maxCoord, 1},
		{123, 4567},
		{maxCoord, maxCoord},
	}
	for _, c := range cases {
		raw, err := Build(100, 100, 0x00, []MinutiaFormat{
			{Type: 1, X: c.x, Y: c.y, Quality: 200, Orientation: 1.0},
		})
		if err != nil {
			t.Fatalf("Build(%d,%d): %v", c.x, c.y, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%d,%d): %v", c.x, c.y, err)
		}
		if got.Minutiae[0].X != c.x || got.Minutiae[0].Y != c.y {
			t.Errorf("round trip (%d,%d) -> (%d,%d); X and Y are not independent",
				c.x, c.y, got.Minutiae[0].X, got.Minutiae[0].Y)
		}
	}
}

// TestOrientationAliasesAgree: angles differing by whole turns are the same
// direction and must encode to the same bytes.
func TestOrientationAliasesAgree(t *testing.T) {
	base := []MinutiaFormat{{Type: 1, X: 10, Y: 10, Quality: 100, Orientation: 0.5}}
	// Every one of these is 0.5 radians plus a whole number of turns, so all
	// of them name the same direction and must encode identically.
	aliases := []float64{
		0.5,
		0.5 + 2*math.Pi,
		0.5 - 2*math.Pi,
		0.5 + 8*math.Pi,
		0.5 - 6*math.Pi,
	}

	var want []byte
	for i, ang := range aliases {
		m := append([]MinutiaFormat(nil), base...)
		m[0].Orientation = ang
		raw, err := Build(64, 64, 0, m)
		if err != nil {
			t.Fatalf("Build(%v): %v", ang, err)
		}
		if i == 0 {
			want = raw
			continue
		}
		if !bytes.Equal(raw, want) {
			t.Errorf("orientation %v encoded differently from 0.5", ang)
		}
	}
}

// TestOrientationOutOfRangeIsNotGarbage: hostile inputs must land on a defined
// value rather than an arbitrary float-to-integer conversion.
func TestOrientationOutOfRangeIsNotGarbage(t *testing.T) {
	for _, ang := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 1e12, -1e12} {
		raw, err := Build(64, 64, 0, []MinutiaFormat{
			{Type: 1, X: 10, Y: 10, Orientation: ang},
		})
		if err != nil {
			t.Fatalf("Build(%v): %v", ang, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%v): %v", ang, err)
		}
		o := got.Minutiae[0].Orientation
		if math.IsNaN(o) || o < 0 || o >= 2*math.Pi {
			t.Errorf("orientation %v encoded to out-of-range %v", ang, o)
		}
	}
}

// TestParse_RejectsShortHeader covers a truncated record header. Every byte is
// zero, so the magic check would also fail - the length check has to come first
// or a short read is reported as "wrong format", which sends a caller looking
// for a format problem instead of a truncated file.
func TestParse_RejectsShortHeader(t *testing.T) {
	for n := 0; n < RecordHeaderLen; n++ {
		if _, err := Parse(make([]byte, n)); !errors.Is(err, ErrTooShort) {
			t.Errorf("Parse(%d bytes) = %v; want ErrTooShort", n, err)
		}
	}
}

// TestParse_RejectsShortBody truncates a record that is otherwise valid, so the
// magic, version and length fields all pass and the data-block length is what
// actually gets tested.
func TestParse_RejectsShortBody(t *testing.T) {
	full, err := Build(64, 64, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for bodyLen := 0; bodyLen < fixedBlockLen; bodyLen++ {
		raw := append([]byte(nil), full[:RecordHeaderLen+bodyLen]...)
		binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)))
		if _, err := Parse(raw); !errors.Is(err, ErrTooShort) {
			t.Errorf("Parse with a %d-byte data block = %v; want ErrTooShort", bodyLen, err)
		}
	}
}

// TestParse_RejectsTruncatedMinutiaeList: the length fields still agree, so only
// the declared minutiae count vs available bytes can catch this.
func TestParse_RejectsTruncatedMinutiaeList(t *testing.T) {
	full, err := Build(64, 64, 0, sample(10))
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < 10*minutiaSize; cut += 3 {
		raw := append([]byte(nil), full[:len(full)-cut]...)
		binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)))
		if _, err := Parse(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse truncated by %d bytes = %v; want ErrMalformed", cut, err)
		}
	}
}

func TestParse_RejectsForeignFormat(t *testing.T) {
	raw, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 1, Y: 1}})
	for _, bad := range []uint32{0x00000001, 0x00000002, 0x00000000, 0xFFFFFFFF} {
		binary.BigEndian.PutUint32(raw[0:4], bad)
		if _, err := Parse(raw); !errors.Is(err, ErrBadMagic) {
			t.Errorf("format 0x%08X = %v; want ErrBadMagic", bad, err)
		}
	}
}

// TestParse_Rejects2011Version: the 2011 edition redefines the minutia record,
// so accepting it would silently misread every coordinate.
func TestParse_Rejects2011Version(t *testing.T) {
	for _, v := range []uint32{0x03000000, 0x02010000, 0x01000000} {
		raw, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 1, Y: 1}})
		binary.BigEndian.PutUint32(raw[4:8], v)
		if _, err := Parse(raw); !errors.Is(err, ErrBadVersion) {
			t.Errorf("version 0x%08X = %v; want ErrBadVersion", v, err)
		}
	}
}

func TestParse_RejectsLengthMismatch(t *testing.T) {
	raw, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 1, Y: 1}})
	binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)+10))
	if _, err := Parse(raw); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("error = %v; want ErrLengthMismatch", err)
	}
}

// TestParse_RejectsMultipleViews: silently reading only the first view would
// discard fingers from a template.
func TestParse_RejectsMultipleViews(t *testing.T) {
	raw, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 1, Y: 1}})
	raw[RecordHeaderLen] = 2 // declare two finger views
	if _, err := Parse(raw); !errors.Is(err, ErrTooManyViews) {
		t.Fatalf("error = %v; want ErrTooManyViews", err)
	}
}

// TestParse_RejectsImplausibleCounts ensures a hostile count cannot drive an
// out-of-range slice before the length check.
func TestParse_RejectsImplausibleCounts(t *testing.T) {
	raw, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 1, Y: 1}})
	body := raw[RecordHeaderLen:]
	binary.BigEndian.PutUint16(body[4:6], 0xFFFF) // 65535 minutiae claimed
	if _, err := Parse(raw); !errors.Is(err, ErrMalformed) {
		t.Fatalf("count of 65535 = %v; want ErrMalformed", err)
	}

	// A count within the count field but above the supported maximum.
	raw2, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 1, Y: 1}})
	binary.BigEndian.PutUint16(raw2[RecordHeaderLen+4:RecordHeaderLen+6], maxMinutiae+1)
	if _, err := Parse(raw2); !errors.Is(err, ErrMalformed) {
		t.Fatalf("count above the cap = %v; want ErrMalformed", err)
	}
}

// TestParse_PreservesExtensionDataVerbatim: extension data is carried through
// untouched rather than reinterpreted.
func TestParse_PreservesExtensionDataVerbatim(t *testing.T) {
	raw, _ := Build(100, 100, 0, []MinutiaFormat{{Type: 1, X: 7, Y: 9, Quality: 5}})
	ext := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}
	withExt := append(append([]byte(nil), raw...), ext...)
	binary.BigEndian.PutUint32(withExt[8:12], uint32(len(withExt)))

	got, err := Parse(withExt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(got.ExtensionData, ext) {
		t.Errorf("ExtensionData = %v; want %v preserved verbatim", got.ExtensionData, ext)
	}
	if got.Minutiae[0].X != 7 || got.Minutiae[0].Y != 9 {
		t.Errorf("minutia before extension = (%d,%d); want (7,9)",
			got.Minutiae[0].X, got.Minutiae[0].Y)
	}
}

func TestBuild_RejectsBadInput(t *testing.T) {
	good := []MinutiaFormat{{Type: 1, X: 10, Y: 10}}
	cases := map[string]struct {
		w, h int
		m    []MinutiaFormat
	}{
		"zero width":         {0, 100, good},
		"zero height":        {100, 0, good},
		"negative width":     {-1, 100, good},
		"x over 14 bits":     {100, 100, []MinutiaFormat{{Type: 1, X: maxCoord + 1, Y: 1}}},
		"y over 14 bits":     {100, 100, []MinutiaFormat{{Type: 1, X: 1, Y: maxCoord + 1}}},
		"dimension overflow": {70000, 70000, good},
		"too many minutiae":  {100, 100, sample(maxMinutiae + 1)},
		"reserved type 0":    {100, 100, []MinutiaFormat{{Type: 0, X: 1, Y: 1}}},
		"reserved type 3":    {100, 100, []MinutiaFormat{{Type: 3, X: 1, Y: 1}}},
		"reserved type 15":   {100, 100, []MinutiaFormat{{Type: 15, X: 1, Y: 1}}},
		"one bad among many": {100, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1}, {Type: 9, X: 2, Y: 2}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(c.w, c.h, 0, c.m); err == nil {
				t.Errorf("Build(%s) = nil error", name)
			}
		})
	}
}

// TestParse_NeverPanicsOnArbitraryBytes: this parser consumes files from an
// external database, so malformed input must error rather than crash enrollment.
func TestParse_NeverPanicsOnArbitraryBytes(t *testing.T) {
	r := rand.New(rand.NewSource(21))
	for i := 0; i < 2000; i++ {
		n := r.Intn(300)
		b := make([]byte, n)
		r.Read(b)
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("Parse panicked on %d random bytes: %v", n, rec)
				}
			}()
			_, _ = Parse(b)
		}()
	}
}

// TestParse_MutationIsDetected: flipping a count field must not yield a record
// that parses to the original minutiae.
func TestParse_MutationIsDetected(t *testing.T) {
	in := sample(20)
	raw, _ := Build(150, 150, 0, in)
	orig, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	mutated := append([]byte(nil), raw...)
	mutated[RecordHeaderLen+4] ^= 0x01 // perturb the minutiae count
	got, err := Parse(mutated)
	if err != nil {
		return // rejecting is fine
	}
	if len(got.Minutiae) == len(orig.Minutiae) && len(in) > 0 {
		t.Error("perturbing the minutiae count produced an identical parse")
	}
}

// TestReservedBitsAreAlwaysZero: the two bits above y are reserved and writing
// them non-zero is a conformance violation that still parses.
func TestReservedBitsAreAlwaysZero(t *testing.T) {
	raw, err := Build(64, 64, 0, []MinutiaFormat{
		{Type: 2, X: maxCoord, Y: maxCoord, Quality: 255, Orientation: 3.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := raw[RecordHeaderLen+fixedBlockLen:][:minutiaSize]
	if binary.BigEndian.Uint16(m[2:4])&0xC000 != 0 {
		t.Errorf("reserved bits set: bytes [2:4] = 0x%04X", binary.BigEndian.Uint16(m[2:4]))
	}
}
