// Package iso19794b implements ISO/IEC 19794-2 finger minutiae records.
//
// Companion to package iso19794, which handles the 19794-4 IMAGE records.
// This file covers the other half of the interoperability story: exporting and
// importing the minutiae TEMPLATES themselves, which is what an existing
// fingerprint database actually stores. Without it, a database can supply raw
// images but never templates.
//
// SCOPE - read this before relying on it.
//
// What is implemented is the FIXED portion of the general-purpose finger
// minutiae record of ISO/IEC 19794-2:2005: the 24-byte general header, the
// finger minutiae data block header (finger view, finger position, impression
// type, finger quality, minutiae count, core point, and the count of possible
// starting points), and the minutiae list itself.
//
// Three things are deliberately NOT implemented:
//
//   - Extension data. Records carrying extensions parse, and their extension
//     bytes are preserved verbatim rather than reinterpreted.
//   - Multiple finger views per record. Exactly one view is read and written.
//     A multi-view record is rejected rather than partially read, because
//     returning only the first view would silently drop fingers from a
//     template.
//   - Ridge count / core-and-delta extended data blocks. They are carried as
//     opaque extension bytes, so they survive a round trip but are not
//     decoded.
//
// PROVENANCE - what is verified and what is not.
//
// The minutiae record layout below is taken from the standard's own normative
// text, which states that the X coordinate occupies the lower fourteen bits of
// the first two bytes, the Y coordinate the lower fourteen bits of the third
// and fourth, that '01' is a ridge ending and '10' a bifurcation, and that the
// angle is scaled to 1.40625 (360/256) degrees per least significant bit. That
// yields exactly the six-byte record implemented here, and those four
// statements are what the tests in this package pin.
//
// The general header is the same 24-byte header package iso19794 already
// parses against the 19794-4 tables.
//
// The two fields marked INFERRED below - the 13-byte length of the finger
// minutiae data block header, and the 12-byte possible starting point record -
// could NOT be checked against the standard's Table 3, which sits behind a
// paywall. Their sizes are self-consistent and every record this package
// writes parses correctly here, but they have not been compared against an
// independently produced record. Treat a wire-format bug in those two fields
// as live until a real third-party record is fed to Parse.
//
// Version handling: only 0x02000000 (19794-2:2005) is accepted. The 2011
// edition is 0x03000000 and is NOT compatible - it redefines the minutia
// record around MINBYTES and a 14-bit-pair layout with a five-byte variant -
// so it is rejected rather than misread.
//
// MINEX III is a different and much larger standard - a certified template
// format - and is NOT implemented here.
package iso19794b

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// RecordHeaderLen is the fixed record header length in bytes, identical to
// ISO/IEC 19794-4 (see package iso19794).
const RecordHeaderLen = 24

// minutiaSize is the length of one minutia record in bytes.
//
// The standard's general-purpose format uses a FIXED six-byte record:
//
//	[0:2]  minutia type (2 bits) + x position (14 bits)
//	[2:4]  reserved (2 bits, zero) + y position (14 bits)
//	[4]    minutia angle, 1.40625 degrees per least significant bit
//	[5]    minutia quality
//
// There is no per-minutia length field in this edition - the 2011 edition
// introduces one, and is not compatible.
const minutiaSize = 6

// maxCoord is the largest value a 14-bit coordinate field can hold. It is far
// above any real fingerprint: a 1000 dpi 500x800 image is still under 1000.
const maxCoord = 0x3FFF

// fixedBlockLen is the finger minutiae data block header length, before the
// variable-length tail.
//
// INFERRED - see the package provenance note. Layout:
//
//	[0]     number of finger views
//	[1]     finger position
//	[2]     impression type
//	[3]     finger quality
//	[4:6]   number of minutiae
//	[6:8]   core point x
//	[8:10]  core point y
//	[10]    core quality
//	[11:13] number of possible starting points
//
// The possible starting points follow, then the minutiae list, then any
// extension bytes. Both variable-length sections are counted before the data
// is sliced, so a hostile count cannot drive an out-of-range access.
const fixedBlockLen = 13

// startingPointSize is the length of one possible starting point record.
//
// INFERRED - see the package provenance note.
const startingPointSize = 12

// maxMinutiae caps how many minutiae a single view may declare. The count
// field is 16 bits, so without this a hostile record could ask for a 65535-
// element slice. No real finger approaches this: a dense 500 dpi print carries
// on the order of a hundred.
const maxMinutiae = 256

// angleUnits is the angular resolution of the 1-byte angle field: the standard
// specifies 1.40625 degrees, which is exactly 360/256, so the field spans a
// full turn in 256 steps. Expressed in radians because that is what the Go
// API uses.
var angleUnits = 2 * math.Pi / 256.0

var (
	ErrTooShort       = errors.New("iso19794b: record truncated")
	ErrBadMagic       = errors.New("iso19794b: not an ISO/IEC 19794-2 minutiae record")
	ErrBadVersion     = errors.New("iso19794b: unsupported record version (only 19794-2:2005 is implemented)")
	ErrLengthMismatch = errors.New("iso19794b: declared record length does not match the data")
	ErrTooManyViews   = errors.New("iso19794b: record declares more than one finger view")
	ErrMalformed      = errors.New("iso19794b: malformed minutiae data block")
)

// MinutiaFormat is the on-disk encoding of one minutia.
type MinutiaFormat struct {
	// Type is 1 for ridge ending and 2 for bifurcation. These are the two
	// values the standard defines; 0 and 3 are reserved.
	Type uint8
	X    uint16
	Y    uint16
	// Quality is 0..255. 0 means "not specified".
	Quality uint8
	// Orientation is a direction in radians in [0, 2*pi). Any real value is
	// accepted on input; Build wraps it into that range, which is what the
	// unsigned on-wire field can represent.
	Orientation float64
}

// Record is a parsed ISO/IEC 19794-2 finger minutiae record.
type Record struct {
	Width  int
	Height int

	FingerPosition uint8
	ImpressionType uint8
	FingerQuality  uint8

	CoreX, CoreY uint16
	CoreQuality  uint8

	Minutiae []MinutiaFormat

	// ExtensionData is preserved verbatim and never reinterpreted.
	ExtensionData []byte
}

// normalizeAngle wraps an angle in radians into [0, 2*pi).
//
// The on-wire angle is a single UNSIGNED byte spanning exactly one full turn,
// so the whole problem is staying inside [0, 2*pi) before converting. Values
// outside that range - including NaN - would otherwise rely on undefined
// float-to-integer conversion behaviour, which the Go specification calls
// implementation-dependent. Wrapping first makes the encoding correct by
// construction and gives NaN and Inf a defined answer (zero, meaning "no
// direction") instead of whatever the architecture happens to produce.
func normalizeAngle(a float64) float64 {
	const twoPi = 2 * math.Pi
	if math.IsNaN(a) || math.IsInf(a, 0) {
		return 0
	}
	return math.Mod(math.Mod(a, twoPi)+twoPi, twoPi)
}

// Parse reads a complete ISO/IEC 19794-2 record.
//
// Parsed minutia orientations come back in radians in [0, 2*pi), which is the
// range the unsigned on-wire field carries.
func Parse(b []byte) (*Record, error) {
	if len(b) < RecordHeaderLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooShort, len(b))
	}
	format := binary.BigEndian.Uint32(b[0:4])
	if format != 0x00000003 { // finger minutiae record
		return nil, fmt.Errorf("%w: format = 0x%08X", ErrBadMagic, format)
	}
	version := binary.BigEndian.Uint32(b[4:8])
	if version != 0x02000000 { // 19794-2:2005
		return nil, fmt.Errorf("%w: version = 0x%08X", ErrBadVersion, version)
	}
	if int(binary.BigEndian.Uint32(b[8:12])) != len(b) {
		return nil, fmt.Errorf("%w: header says %d, got %d",
			ErrLengthMismatch, binary.BigEndian.Uint32(b[8:12]), len(b))
	}

	width := int(binary.BigEndian.Uint16(b[14:16]))
	height := int(binary.BigEndian.Uint16(b[12:14]))

	body := b[RecordHeaderLen:]
	if len(body) < fixedBlockLen {
		return nil, fmt.Errorf("%w: data block too short", ErrTooShort)
	}

	views := body[0]
	if views != 1 {
		// Reading only the first view would silently discard the others, which
		// for a template means losing fingers. Refuse instead.
		return nil, fmt.Errorf("%w: %d views", ErrTooManyViews, views)
	}

	r := &Record{
		Width:          width,
		Height:         height,
		FingerPosition: body[1],
		ImpressionType: body[2],
		FingerQuality:  body[3],
		CoreX:          binary.BigEndian.Uint16(body[6:8]),
		CoreY:          binary.BigEndian.Uint16(body[8:10]),
		CoreQuality:    body[10],
	}

	numMinutiae := int(binary.BigEndian.Uint16(body[4:6]))
	numStarting := int(binary.BigEndian.Uint16(body[11:13]))

	if numMinutiae > maxMinutiae {
		// Checked before the length arithmetic so an implausible count is
		// reported as such rather than as a length shortfall.
		return nil, fmt.Errorf("%w: implausible minutiae count %d", ErrMalformed, numMinutiae)
	}

	// Validate the variable-length tail BEFORE slicing, so a hostile count
	// cannot drive an out-of-range access.
	need := fixedBlockLen + numStarting*startingPointSize + numMinutiae*minutiaSize
	if len(body) < need {
		return nil, fmt.Errorf("%w: %d minutiae + %d starting points need %d bytes, have %d",
			ErrMalformed, numMinutiae, numStarting, need, len(body))
	}

	// The minutiae list sits after the starting points.
	off := fixedBlockLen + numStarting*startingPointSize
	// Everything after the minutiae list is extension data, kept verbatim.
	tail := off + numMinutiae*minutiaSize

	r.Minutiae = make([]MinutiaFormat, 0, numMinutiae)
	for i := 0; i < numMinutiae; i++ {
		m := body[off+i*minutiaSize : off+(i+1)*minutiaSize]
		xy := binary.BigEndian.Uint16(m[0:2])
		yy := binary.BigEndian.Uint16(m[2:4])

		r.Minutiae = append(r.Minutiae, MinutiaFormat{
			Type:        uint8(xy >> 14), // 2-bit type in the top bits
			X:           xy & 0x3FFF,     // x in the low 14 bits
			Y:           yy & 0x3FFF,     // y in the low 14 bits
			Quality:     m[5],
			Orientation: float64(m[4]) * angleUnits,
		})
	}

	if tail < len(body) {
		r.ExtensionData = append([]byte(nil), body[tail:]...)
	}
	return r, nil
}

// Build serialises minutiae as a single-view ISO/IEC 19794-2 record.
//
// What Build can express is deliberately narrow, and a re-serialisation of a
// parsed record is therefore NOT a faithful copy of an arbitrary one:
//
//   - Finger position and the minutiae themselves are caller-supplied.
//   - Resolution is fixed at 500 dpi in pixels-per-inch units, matching what
//     pkg/biometrics/iso19794 writes for images.
//   - Impression type is fixed to 0 (live-scan plain) and the core point is
//     fixed to (0,0) with zero quality. Neither is an input. A record that
//     arrived with a real core point or a rolled impression loses both when
//     written back out by this function.
//   - No possible starting points are computed. Writing a fabricated set
//     would be worse than writing none.
//
// Parse is the lossless direction; Build is the narrow one.
func Build(width, height int, fingerPosition uint8, minutiae []MinutiaFormat) ([]byte, error) {
	if width <= 0 || height <= 0 || width > 0xFFFF || height > 0xFFFF {
		return nil, fmt.Errorf("iso19794b: invalid dimensions %dx%d", width, height)
	}
	if len(minutiae) > maxMinutiae {
		return nil, fmt.Errorf("iso19794b: %d minutiae exceeds the supported maximum of %d", len(minutiae), maxMinutiae)
	}
	for i, m := range minutiae {
		// The standard defines only '01' (ridge ending) and '10'
		// (bifurcation). A reserved value here would not fail on re-read, it
		// would just match nothing.
		if m.Type != 1 && m.Type != 2 {
			return nil, fmt.Errorf("iso19794b: minutia %d has type %d; only 1 (ridge ending) and 2 (bifurcation) are defined", i, m.Type)
		}
		if m.X > maxCoord || m.Y > maxCoord {
			return nil, fmt.Errorf("iso19794b: minutia %d at (%d,%d) exceeds the 14-bit field", i, m.X, m.Y)
		}
	}

	need := fixedBlockLen + len(minutiae)*minutiaSize
	out := make([]byte, RecordHeaderLen+need)

	binary.BigEndian.PutUint32(out[0:4], 0x00000003)
	binary.BigEndian.PutUint32(out[4:8], 0x02000000)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(out)))
	binary.BigEndian.PutUint16(out[12:14], uint16(height))
	binary.BigEndian.PutUint16(out[14:16], uint16(width))
	// out[16] is resolution units: 0 means pixels per inch, which is what the
	// two 500 values below are expressed in. It stays zero by construction.
	binary.BigEndian.PutUint16(out[17:19], 500) // resolution x, dpi
	binary.BigEndian.PutUint16(out[19:21], 500) // resolution y, dpi
	out[21] = 1                                 // number of finger views
	out[22] = 1                                 // number of subjects
	out[23] = 0                                 // finger quality at header level

	body := out[RecordHeaderLen:]
	body[0] = 1 // one finger view
	body[1] = fingerPosition
	body[2] = 0 // impression type: live-scan plain
	body[3] = 0 // finger quality
	binary.BigEndian.PutUint16(body[4:6], uint16(len(minutiae)))
	binary.BigEndian.PutUint16(body[6:8], 0) // core x
	binary.BigEndian.PutUint16(body[8:10], 0)
	body[10] = 0 // core quality
	binary.BigEndian.PutUint16(body[11:13], 0)

	off := fixedBlockLen
	for i, m := range minutiae {
		e := body[off+i*minutiaSize : off+(i+1)*minutiaSize]
		// Type occupies the top 2 bits, x the low 14. The 2 bits between y
		// and the next field are reserved and written as zero.
		binary.BigEndian.PutUint16(e[0:2], uint16(m.Type&0x03)<<14|m.X&0x3FFF)
		binary.BigEndian.PutUint16(e[2:4], m.Y&0x3FFF)
		e[4] = uint8(math.Round(normalizeAngle(m.Orientation) / angleUnits))
		e[5] = m.Quality
	}
	return out, nil
}
