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
			Quality:     uint8(1 + r.Intn(100)),
			Orientation: r.Float64() * 2 * math.Pi,
		})
	}
	return out
}

// TestRecordHeaderMatchesTheStandard pins the general header offset by offset.
//
// This is the test that catches the mistake that actually mattered: the 19794-2
// header is NOT laid out like the 19794-4 header that package iso19794 parses,
// even though both are 24 bytes. 19794-2 puts the certification flag and the
// 12-bit capture device ID at [12:14]; 19794-4 puts image height there.
func TestRecordHeaderMatchesTheStandard(t *testing.T) {
	raw, err := Build(640, 480, 2, 0, 90, []MinutiaFormat{
		{Type: 1, X: 100, Y: 200, Quality: 80, Orientation: 0},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	h := raw[:RecordHeaderLen]

	if got, want := h[0:4], []byte("FMR\x00"); !bytes.Equal(got, want) {
		t.Errorf("identifier = %q; want %q. The standard specifies the ASCII string FMR, not a numeric type code.", got, want)
	}
	if got, want := h[4:8], []byte(" 20\x00"); !bytes.Equal(got, want) {
		t.Errorf("version = %q; want %q. The standard specifies the ASCII string \" 20\", not the integer 0x02000000.", got, want)
	}
	if got := binary.BigEndian.Uint32(h[8:12]); int(got) != len(raw) {
		t.Errorf("record length = %d; want %d", got, len(raw))
	}
	// Certification flag is the high nibble of [12]; the device ID is the low
	// 12 bits spanning [12:14].
	if h[12]&0xF0 != 0 {
		t.Errorf("certification nibble = 0x%X; want 0 for an uncertified record", h[12]&0xF0)
	}
	if got := uint16(h[12]&0x0F)<<8 | uint16(h[13]); got != 0 {
		t.Errorf("capture device ID = %d; want 0 (unreported)", got)
	}
	if got := binary.BigEndian.Uint16(h[14:16]); int(got) != 640 {
		t.Errorf("width at [14:16] = %d; want 640. Note 19794-4 puts HEIGHT here.", got)
	}
	if got := binary.BigEndian.Uint16(h[16:18]); int(got) != 480 {
		t.Errorf("height at [16:18] = %d; want 480. Note 19794-4 puts width and a resolution-units byte here.", got)
	}
	if got := binary.BigEndian.Uint16(h[18:20]); got != 500 {
		t.Errorf("X resolution at [18:20] = %d; want 500", got)
	}
	if got := binary.BigEndian.Uint16(h[20:22]); got != 500 {
		t.Errorf("Y resolution at [20:22] = %d; want 500", got)
	}
	if h[22] != 1 {
		t.Errorf("number of finger views at [22] = %d; want 1", h[22])
	}
	if h[23] != 0 {
		t.Errorf("reserved byte at [23] = %d; want 0", h[23])
	}
	if RecordHeaderLen != 24 {
		t.Errorf("RecordHeaderLen = %d; the standard fixes the header at 24 bytes", RecordHeaderLen)
	}
}

// TestFingerHeaderMatchesTheStandard pins the per-finger header, which the
// standard fixes at FOUR bytes with five fields.
func TestFingerHeaderMatchesTheStandard(t *testing.T) {
	raw, err := Build(200, 200, 6, 1, 75, []MinutiaFormat{
		{Type: 1, X: 5, Y: 6, Quality: 90, Orientation: 0},
		{Type: 2, X: 7, Y: 8, Quality: 90, Orientation: 0},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fh := raw[RecordHeaderLen:][:FingerHeaderLen]

	if FingerHeaderLen != 4 {
		t.Errorf("FingerHeaderLen = %d; the standard fixes the finger header at 4 bytes", FingerHeaderLen)
	}
	if fh[0] != 6 {
		t.Errorf("finger position = %d; want 6 (left thumb)", fh[0])
	}
	if got := fh[1] >> 4; got != 0 {
		t.Errorf("view number (high nibble) = %d; want 0 for a single view", got)
	}
	if got := fh[1] & 0x0F; got != 1 {
		t.Errorf("impression type (low nibble) = %d; want 1 (live scan rolled)", got)
	}
	if fh[2] != 75 {
		t.Errorf("finger image quality = %d; want 75", fh[2])
	}
	if fh[3] != 2 {
		t.Errorf("number of minutiae = %d; want 2. The standard uses a ONE byte count.", fh[3])
	}
}

// TestMinutiaRecordMatchesTheStandard pins the six-byte minutia record.
func TestMinutiaRecordMatchesTheStandard(t *testing.T) {
	cases := []struct {
		name              string
		m                 MinutiaFormat
		firstTwo, nextTwo uint16 // the two 16-bit words, fully specified
		angle             uint8
		quality           uint8
	}{
		{
			name:     "ridge ending at origin",
			m:        MinutiaFormat{Type: 1, X: 0, Y: 0, Quality: 1, Orientation: 0},
			firstTwo: 0x4000, // '01' in the top two bits
			nextTwo:  0x0000,
			angle:    0,
			quality:  1,
		},
		{
			name:     "bifurcation at the coordinate maximum",
			m:        MinutiaFormat{Type: 2, X: maxCoord, Y: maxCoord, Quality: 100, Orientation: 0},
			firstTwo: 0x8000 | maxCoord, // '10'
			nextTwo:  0x0000 | maxCoord, // reserved bits zero
			angle:    0,
			quality:  100,
		},
		{
			// The standard's own worked example: orientation 16 is 22.5 degrees.
			name:     "22.5 degree orientation",
			m:        MinutiaFormat{Type: 1, X: 1234, Y: 5678, Quality: 50, Orientation: 22.5 * math.Pi / 180},
			firstTwo: 0x4000 | 1234,
			nextTwo:  0x0000 | 5678,
			angle:    16,
			quality:  50,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := Build(64, 64, 0, 0, 100, []MinutiaFormat{c.m})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			m := raw[RecordHeaderLen+FingerHeaderLen:][:minutiaSize]

			if got := binary.BigEndian.Uint16(m[0:2]); got != c.firstTwo {
				t.Errorf("bytes [0:2] = 0x%04X; want 0x%04X", got, c.firstTwo)
			}
			if got := binary.BigEndian.Uint16(m[2:4]); got != c.nextTwo {
				t.Errorf("bytes [2:4] = 0x%04X; want 0x%04X (reserved bits must be zero)", got, c.nextTwo)
			}
			if m[4] != c.angle {
				t.Errorf("orientation byte = %d; want %d", m[4], c.angle)
			}
			if m[5] != c.quality {
				t.Errorf("quality byte = %d; want %d", m[5], c.quality)
			}
			if len(m) != 6 {
				t.Errorf("minutia record is %d bytes; the standard fixes it at 6", len(m))
			}
		})
	}
}

// TestAngleIs360Over256 asserts the granularity the standard names.
func TestAngleIs360Over256(t *testing.T) {
	if deg := angleUnits * 180 / math.Pi; math.Abs(deg-1.40625) > 1e-12 {
		t.Fatalf("one LSB is %v degrees; the standard specifies 1.40625", deg)
	}
	// The standard's worked example: byte value 16 means 22.5 degrees.
	if got := float64(16) * angleUnits * 180 / math.Pi; math.Abs(got-22.5) > 1e-9 {
		t.Errorf("orientation byte 16 = %v degrees; the standard's example says 22.5", got)
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
	for _, n := range []int{0, 1, 2, 12, 40, 120, 255} {
		in := sample(n)
		raw, err := Build(200, 200, 1, 0, 85, in)
		if err != nil {
			t.Fatalf("Build(%d minutiae): %v", n, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%d minutiae): %v", n, err)
		}
		if len(got.Views) != 1 {
			t.Fatalf("got %d views; want 1", len(got.Views))
		}
		out := got.Views[0].Minutiae
		if len(out) != len(in) {
			t.Fatalf("got %d minutiae; want %d", len(out), len(in))
		}
		for i := range in {
			g, w := out[i], in[i]
			if g.Type != w.Type || g.X != w.X || g.Y != w.Y || g.Quality != w.Quality {
				t.Fatalf("minutia %d: got %+v; want %+v", i, g, w)
			}
			// The angle field is 8-bit, so it is lossy by design.
			if delta := angleDelta(g.Orientation, w.Orientation); delta > halfLSB+1e-12 {
				t.Errorf("minutia %d orientation drifted by %v (half LSB is %v; got %v want %v)",
					i, delta, halfLSB, g.Orientation, w.Orientation)
			}
		}
		if got.Width != 200 || got.Height != 200 {
			t.Errorf("dimensions = %dx%d; want 200x200", got.Width, got.Height)
		}
		if got.Views[0].FingerPosition != 1 {
			t.Errorf("FingerPosition = %d; want 1", got.Views[0].FingerPosition)
		}
		if got.Views[0].Quality != 85 {
			t.Errorf("finger quality = %d; want 85", got.Views[0].Quality)
		}
		if got.ResolutionX != 500 || got.ResolutionY != 500 {
			t.Errorf("resolution = %dx%d; want 500x500", got.ResolutionX, got.ResolutionY)
		}
	}
}

// TestXAndYAreIndependentFields guards against X and Y being packed into one
// field: a single narrow pair silently mis-places every coordinate, and the
// round trip still succeeds.
func TestXAndYAreIndependentFields(t *testing.T) {
	cases := []struct{ x, y uint16 }{
		{0, 0},
		{maxCoord, 0},
		{0, maxCoord}, // the case a packed field destroys
		{1, maxCoord},
		{maxCoord, 1},
		{123, 4567},
		{maxCoord, maxCoord},
	}
	for _, c := range cases {
		raw, err := Build(100, 100, 0, 0, 100, []MinutiaFormat{
			{Type: 1, X: c.x, Y: c.y, Quality: 60, Orientation: 1.0},
		})
		if err != nil {
			t.Fatalf("Build(%d,%d): %v", c.x, c.y, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%d,%d): %v", c.x, c.y, err)
		}
		m := got.Views[0].Minutiae[0]
		if m.X != c.x || m.Y != c.y {
			t.Errorf("round trip (%d,%d) -> (%d,%d); X and Y are not independent",
				c.x, c.y, m.X, m.Y)
		}
	}
}

// TestOrientationAliasesAgree: angles differing by whole turns are the same
// direction and must encode to the same bytes.
func TestOrientationAliasesAgree(t *testing.T) {
	base := []MinutiaFormat{{Type: 1, X: 10, Y: 10, Quality: 70, Orientation: 0.5}}
	// Every one of these is 0.5 radians plus a whole number of turns.
	aliases := []float64{0.5, 0.5 + 2*math.Pi, 0.5 - 2*math.Pi, 0.5 + 8*math.Pi, 0.5 - 6*math.Pi}

	var want []byte
	for i, ang := range aliases {
		m := append([]MinutiaFormat(nil), base...)
		m[0].Orientation = ang
		raw, err := Build(64, 64, 0, 0, 100, m)
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
		raw, err := Build(64, 64, 0, 0, 100, []MinutiaFormat{
			{Type: 1, X: 10, Y: 10, Quality: 70, Orientation: ang},
		})
		if err != nil {
			t.Fatalf("Build(%v): %v", ang, err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%v): %v", ang, err)
		}
		o := got.Views[0].Minutiae[0].Orientation
		if math.IsNaN(o) || o < 0 || o >= 2*math.Pi {
			t.Errorf("orientation %v encoded to out-of-range %v", ang, o)
		}
	}
}

func TestParse_RejectsShortHeader(t *testing.T) {
	for n := 0; n < RecordHeaderLen; n++ {
		if _, err := Parse(make([]byte, n)); !errors.Is(err, ErrTooShort) {
			t.Errorf("Parse(%d bytes) = %v; want ErrTooShort", n, err)
		}
	}
}

// TestParse_RejectsForeignIdentifierAndVersion pins the two string-valued
// header fields, which an earlier draft of this package got numerically wrong.
func TestParse_RejectsForeignIdentifierAndVersion(t *testing.T) {
	good, err := Build(64, 64, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 50}})
	if err != nil {
		t.Fatal(err)
	}
	// The 19794-5 style numeric codes are NOT valid 19794-2 identifiers.
	for _, bad := range []uint32{0x00000003, 0x00000002, 0x00000001, 0x00000000} {
		raw := append([]byte(nil), good...)
		binary.BigEndian.PutUint32(raw[0:4], bad)
		if _, err := Parse(raw); !errors.Is(err, ErrBadMagic) {
			t.Errorf("identifier 0x%08X = %v; want ErrBadMagic", bad, err)
		}
	}
	// Versions are ASCII strings, so the 2011 edition is " 30".
	for _, v := range []string{" 30\x00", " 10\x00", "\x00\x00\x00\x00", "2 0\x00"} {
		raw := append([]byte(nil), good...)
		copy(raw[4:8], v)
		if _, err := Parse(raw); !errors.Is(err, ErrBadVersion) {
			t.Errorf("version %q = %v; want ErrBadVersion", v, err)
		}
	}
}

func TestParse_RejectsLengthMismatch(t *testing.T) {
	raw, _ := Build(100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 50}})
	binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)+10))
	if _, err := Parse(raw); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("error = %v; want ErrLengthMismatch", err)
	}
}

// TestParse_RejectsTruncatedBody exercises each truncation point: the finger
// header, the minutiae list, and the extended data length field.
func TestParse_RejectsTruncatedBody(t *testing.T) {
	full, err := Build(64, 64, 0, 0, 100, sample(10))
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut <= FingerHeaderLen+10*minutiaSize+extAreaLenSize; cut++ {
		raw := append([]byte(nil), full[:len(full)-cut]...)
		binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)))
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse truncated by %d bytes = nil error; want a rejection", cut)
		}
	}
}

// TestParse_RejectsTrailingBytes: extra data that the view count does not
// account for means the record disagrees with itself.
func TestParse_RejectsTrailingBytes(t *testing.T) {
	raw, _ := Build(64, 64, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 50}})
	raw = append(raw, 0xDE, 0xAD)
	binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)))
	if _, err := Parse(raw); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v; want ErrMalformed", err)
	}
}

// TestParse_PreservesExtendedDataVerbatim: the area is carried through
// untouched. Ridge count and core/delta blocks survive, undecoded.
func TestParse_PreservesExtendedDataVerbatim(t *testing.T) {
	full, err := Build(100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 7, Y: 9, Quality: 55}})
	if err != nil {
		t.Fatal(err)
	}

	// One block: type 0x0002 (core and delta), length 6, six bytes of data.
	block := make([]byte, 0, extBlockHeaderLen+6)
	block = append(block, 0x00, 0x02)
	block = append(block, 0x00, 0x06)
	block = append(block, 1, 2, 3, 4, 5, 6)

	area := append([]byte{byte(len(block) >> 8), byte(len(block))}, block...)

	raw := append(append([]byte(nil), full[:len(full)-extAreaLenSize]...), area...)
	binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)))

	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	v := got.Views[0]
	if !bytes.Equal(v.ExtendedData, block) {
		t.Errorf("ExtendedData = %v; want %v preserved verbatim", v.ExtendedData, block)
	}
	if v.Minutiae[0].X != 7 || v.Minutiae[0].Y != 9 {
		t.Errorf("minutia before the extended area = (%d,%d); want (7,9)", v.Minutiae[0].X, v.Minutiae[0].Y)
	}
}

// TestParse_RejectsOversizedExtendedDataArea: the area length is attacker
// controlled, so it must be validated before slicing.
func TestParse_RejectsOversizedExtendedDataArea(t *testing.T) {
	raw, _ := Build(64, 64, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 50}})
	at := len(raw) - extAreaLenSize
	binary.BigEndian.PutUint16(raw[at:], 0xFFFF)
	if _, err := Parse(raw); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v; want ErrMalformed", err)
	}
}

func TestBuild_RejectsBadInput(t *testing.T) {
	good := []MinutiaFormat{{Type: 1, X: 10, Y: 10, Quality: 10}}
	cases := map[string]struct {
		w, h             int
		fp, imp, quality uint8
		m                []MinutiaFormat
	}{
		"zero width":          {0, 100, 0, 0, 100, good},
		"zero height":         {100, 0, 0, 0, 100, good},
		"negative width":      {-1, 100, 0, 0, 100, good},
		"dimension overflow":  {70000, 70000, 0, 0, 100, good},
		"finger position 11":  {100, 100, 11, 0, 100, good},
		"impression 4":        {100, 100, 0, 4, 100, good},
		"impression 7":        {100, 100, 0, 7, 100, good},
		"impression 9":        {100, 100, 0, 9, 100, good},
		"finger quality 101":  {100, 100, 0, 0, 101, good},
		"x over 14 bits":      {100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: maxCoord + 1, Y: 1, Quality: 10}}},
		"y over 14 bits":      {100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: maxCoord + 1, Quality: 10}}},
		"minutia quality 0":   {100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 0}}},
		"minutia quality 101": {100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 101}}},
		"reserved type 3":     {100, 100, 0, 0, 100, []MinutiaFormat{{Type: 3, X: 1, Y: 1, Quality: 10}}},
		"too many minutiae":   {100, 100, 0, 0, 100, sample(256)},
		"one bad among many":  {100, 100, 0, 0, 100, []MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 10}, {Type: 3, X: 2, Y: 2, Quality: 10}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(c.w, c.h, c.fp, c.imp, c.quality, c.m); err == nil {
				t.Errorf("Build(%s) = nil error", name)
			}
		})
	}
}

// TestParse_NeverPanicsOnArbitraryBytes: this parser consumes files from an
// external database, so malformed input must error rather than crash enrollment.
func TestParse_NeverPanicsOnArbitraryBytes(t *testing.T) {
	r := rand.New(rand.NewSource(21))
	for i := 0; i < 3000; i++ {
		n := r.Intn(300)
		b := make([]byte, n)
		r.Read(b)
		// Force a valid prefix sometimes so execution gets past the identifier
		// check and exercises the length arithmetic.
		if n >= RecordHeaderLen && i%3 == 0 {
			copy(b[0:4], formatIdentifier)
			copy(b[4:8], version2005)
			binary.BigEndian.PutUint32(b[8:12], uint32(n))
			b[22] = byte(r.Intn(4))
		}
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
