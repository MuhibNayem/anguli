// Package iso19794b implements ISO/IEC 19794-2:2005 finger minutiae records.
//
// Companion to package iso19794, which handles the 19794-4 IMAGE records.
// This file covers the other half of the interoperability story: exporting and
// importing the minutiae TEMPLATES themselves, which is what an existing
// fingerprint database actually stores. Without it, a database can supply raw
// images but never templates.
//
// # Layout
//
// A record is a 24-byte general header followed by one finger view per finger:
//
//	General header (24 bytes)
//	  [0:4]   format identifier, the ASCII string "FMR\0"
//	  [4:8]   version, the ASCII string " 20\0" for the 2005 edition
//	  [8:12]  total record length in bytes
//	  [12]    certification block present (high 4 bits) + capture device ID
//	  [13]    ... device ID continues into the low 12 bits of [12:14]
//	  [14:16] image width in pixels
//	  [16:18] image height in pixels
//	  [18:20] X resolution
//	  [20:22] Y resolution
//	  [22]    number of finger views in this record
//	  [23]    reserved, zero
//
//	Finger view (repeated)
//	  [0]     finger position (0..10)
//	  [1]     view number (high 4 bits) + impression type (low 4 bits)
//	  [2]     finger image quality, 0..100
//	  [3]     number of minutiae
//	  N x 6   minutiae
//	  [2]     extended data area length; if non-zero, that many bytes follow
//
//	Minutia (6 bytes)
//	  [0:2]   minutia type (high 2 bits) + X position (low 14 bits)
//	  [2:4]   reserved (high 2 bits) + Y position (low 14 bits)
//	  [4]     orientation, 1.40625 (360/256) degrees per least significant bit
//	  [5]     minutia quality, 1..100
//
//	Extended data block (repeated within the area)
//	  [0:2]   block type; 0x0001 ridge count, 0x0002 core and delta,
//	          0x0003 zonal quality, non-zero first byte is vendor-defined
//	  [2:4]   block length
//	  [n]     block data
//
// # The 19794-2 header is NOT the 19794-4 header
//
// The two standards share a 24-byte header length but not a layout. 19794-4
// puts image height at [12:14], width at [14:16] and a resolution-units byte
// at [16]; 19794-2 puts a certification flag and capture device ID at [12:14],
// width at [14:16] and height at [16:18]. Reusing the 19794-4 offsets here
// reads a capture device ID as a pixel width and yields plausible nonsense, so
// the offsets below are written out explicitly and asserted in the tests.
//
// # Scope
//
//   - Core and delta points, ridge counts and zonal quality live in the
//     optional extended data area. Those bytes are preserved verbatim and are
//     NOT decoded.
//   - The certification block (Appendix D) is not parsed. The flag is carried
//     through so a caller can tell whether to expect one.
//
// # Provenance
//
// Every offset above is taken from the standard's normative text and its
// byte-offset tables, not inferred. The fields that were previously guessed -
// the finger header and its byte count, the format identifier, the version
// encoding, the minutiae count width, and the minutiae quality range - were all
// wrong in an earlier draft of this package and are now pinned by
// TestRecordHeaderMatchesTheStandard, TestFingerHeaderMatchesTheStandard and
// TestMinutiaRecordMatchesTheStandard.
//
// Version handling: only the 2005 edition is accepted. The 2011 edition
// restructures the record and is rejected rather than misread. MINEX III is a
// certified template format and a much larger standard, and is NOT implemented.
package iso19794b

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Fixed field sizes, in bytes.
const (
	// RecordHeaderLen is the general record header length.
	RecordHeaderLen = 24
	// FingerHeaderLen is the per-finger-view header length.
	FingerHeaderLen = 4
	// minutiaSize is the fixed length of one minutia record.
	minutiaSize = 6
	// extAreaLenSize is the extended data area length field.
	extAreaLenSize = 2
	// extBlockHeaderLen is the per-block type + length header.
	extBlockHeaderLen = 4
)

// maxMinutiae is the largest count the one-byte field can express. No real
// finger approaches it; a dense 500 dpi print carries on the order of a hundred.
const maxMinutiae = 255

// maxCoord is the largest value a 14-bit coordinate field can hold.
const maxCoord = 0x3FFF

// formatIdentifier is the ASCII string "FMR\0". The standard specifies this as
// a four-character string, not as a numeric type identifier: the 0x00000003
// style codes belong to the 19794-5 BDIR formats and are NOT a valid 19794-2
// record identifier.
var formatIdentifier = []byte{'F', 'M', 'R', 0x00} // 0x464D5200

// version2005 is the version string for the 2005 edition: a space followed by
// the two ASCII digits of the edition, then a NULL terminator. It is a string,
// not the integer 0x02000000.
var version2005 = []byte{' ', '2', '0', 0x00} // 0x20323000

// angleUnits is the angular resolution of the orientation byte: the standard
// specifies 1.40625 degrees, which is exactly 360/256, so the field spans a
// full turn in 256 steps. Expressed in radians because that is what the Go
// API uses.
var angleUnits = 2 * math.Pi / 256.0

var (
	ErrTooShort       = errors.New("iso19794b: record truncated")
	ErrBadMagic       = errors.New("iso19794b: not an ISO/IEC 19794-2 minutiae record")
	ErrBadVersion     = errors.New("iso19794b: unsupported record version (only 19794-2:2005 is implemented)")
	ErrLengthMismatch = errors.New("iso19794b: declared record length does not match the data")
	ErrMalformed      = errors.New("iso19794b: malformed record structure")
	ErrBadFingerPos   = errors.New("iso19794b: finger position out of range")
	ErrBadImpression  = errors.New("iso19794b: impression type out of range")
	ErrBadQuality     = errors.New("iso19794b: quality value out of range")
)

// MinutiaFormat is one minutia as the standard encodes it.
type MinutiaFormat struct {
	// Type is 1 for ridge ending, 2 for bifurcation, 0 for "other".
	Type uint8
	X    uint16
	Y    uint16
	// Quality is 1..100 as the standard requires. It is not 0..255: a value
	// of zero is not a valid minutia quality.
	Quality uint8
	// Orientation is a direction in radians in [0, 2*pi). Any real value is
	// accepted on input; Build wraps it into that range, which is what the
	// unsigned on-wire byte can represent.
	Orientation float64
}

// View is one finger view within a record.
type View struct {
	// FingerPosition is 0 for unknown, 1..5 right thumb..little,
	// 6..10 left thumb..little.
	FingerPosition uint8
	// ViewNumber is 0 when the record holds a single view of this finger.
	ViewNumber uint8
	// ImpressionType: 0 live plain, 1 live rolled, 2 non-live plain,
	// 3 non-live rolled, 8 swipe. Values 4..7 are not permitted.
	ImpressionType uint8
	// Quality is the overall finger image quality, 0..100.
	Quality  uint8
	Minutiae []MinutiaFormat
	// ExtendedData is the optional extended data area, preserved verbatim.
	// Core and delta, ridge counts and zonal quality live here and are not
	// decoded.
	ExtendedData []byte
}

// Record is a parsed ISO/IEC 19794-2:2005 finger minutiae record.
type Record struct {
	// CertifiedBlock reports whether a certification block (Appendix D)
	// follows the finger views. The block itself is not parsed.
	CertifiedBlock bool
	// CaptureDeviceID is the 12-bit device identifier; zero means unreported.
	CaptureDeviceID uint16
	// Width and Height are the original image dimensions in pixels.
	Width, Height int
	// ResolutionX and ResolutionY come from the record header.
	ResolutionX, ResolutionY uint16
	Views                    []View
}

// normalizeAngle wraps an angle in radians into [0, 2*pi).
//
// The on-wire angle is a single UNSIGNED byte spanning exactly one full turn,
// so the whole problem is staying inside [0, 2*pi) before converting. Values
// outside that range - including NaN - would otherwise rely on undefined
// float-to-integer conversion behaviour, which the Go specification calls
// implementation-dependent. Wrapping first makes the encoding correct by
// construction and gives NaN and Inf a defined answer (zero) instead of
// whatever the architecture happens to produce.
func normalizeAngle(a float64) float64 {
	const twoPi = 2 * math.Pi
	if math.IsNaN(a) || math.IsInf(a, 0) {
		return 0
	}
	return math.Mod(math.Mod(a, twoPi)+twoPi, twoPi)
}

// Parse reads a complete ISO/IEC 19794-2:2005 record.
//
// Orientations come back in radians in [0, 2*pi), the range the unsigned
// on-wire byte carries.
func Parse(b []byte) (*Record, error) {
	if len(b) < RecordHeaderLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooShort, len(b))
	}
	if !bytes.Equal(b[0:4], formatIdentifier) {
		return nil, fmt.Errorf("%w: identifier = %q", ErrBadMagic, b[0:4])
	}
	if !bytes.Equal(b[4:8], version2005) {
		return nil, fmt.Errorf("%w: version = %q", ErrBadVersion, b[4:8])
	}
	if int(binary.BigEndian.Uint32(b[8:12])) != len(b) {
		return nil, fmt.Errorf("%w: header says %d, got %d",
			ErrLengthMismatch, binary.BigEndian.Uint32(b[8:12]), len(b))
	}

	r := &Record{
		CertifiedBlock:  b[12]&0xF0 != 0, // high nibble
		CaptureDeviceID: uint16(b[12]&0x0F)<<8 | uint16(b[13]),
		Width:           int(binary.BigEndian.Uint16(b[14:16])),
		Height:          int(binary.BigEndian.Uint16(b[16:18])),
		ResolutionX:     binary.BigEndian.Uint16(b[18:20]),
		ResolutionY:     binary.BigEndian.Uint16(b[20:22]),
	}

	numViews := int(b[22])
	r.Views = make([]View, 0, numViews)

	off := RecordHeaderLen
	for i := 0; i < numViews; i++ {
		if len(b)-off < FingerHeaderLen {
			return nil, fmt.Errorf("%w: view %d header truncated at offset %d", ErrMalformed, i, off)
		}
		h := b[off : off+FingerHeaderLen]
		v := View{
			FingerPosition: h[0],
			ViewNumber:     h[1] >> 4, // high nibble
			ImpressionType: h[1] & 0x0F,
			Quality:        h[2],
		}
		numMinutiae := int(h[3])
		off += FingerHeaderLen

		need := numMinutiae * minutiaSize
		if len(b)-off < need {
			return nil, fmt.Errorf("%w: view %d declares %d minutiae needing %d bytes, %d remain",
				ErrMalformed, i, numMinutiae, need, len(b)-off)
		}
		if need > 0 {
			v.Minutiae = make([]MinutiaFormat, 0, numMinutiae)
			for j := 0; j < numMinutiae; j++ {
				m := b[off+j*minutiaSize : off+(j+1)*minutiaSize]
				xy := binary.BigEndian.Uint16(m[0:2])
				yy := binary.BigEndian.Uint16(m[2:4])
				v.Minutiae = append(v.Minutiae, MinutiaFormat{
					Type:        uint8(xy >> 14),
					X:           xy & 0x3FFF,
					Y:           yy & 0x3FFF,
					Orientation: float64(m[4]) * angleUnits,
					Quality:     m[5],
				})
			}
		}
		off += need

		if len(b)-off < extAreaLenSize {
			return nil, fmt.Errorf("%w: view %d extended data length truncated at offset %d",
				ErrMalformed, i, off)
		}
		extLen := int(binary.BigEndian.Uint16(b[off : off+extAreaLenSize]))
		off += extAreaLenSize
		if len(b)-off < extLen {
			return nil, fmt.Errorf("%w: view %d extended data area claims %d bytes, %d remain",
				ErrMalformed, i, extLen, len(b)-off)
		}
		if extLen > 0 {
			// Kept verbatim. The individual blocks inside are not decoded;
			// see the package scope note.
			v.ExtendedData = append([]byte(nil), b[off:off+extLen]...)
			off += extLen
		}
		r.Views = append(r.Views, v)
	}

	if off != len(b) {
		// Trailing bytes mean the view count and the data disagree. Ignoring
		// them would silently drop a finger, so this is an error.
		return nil, fmt.Errorf("%w: %d trailing bytes after %d views",
			ErrMalformed, len(b)-off, numViews)
	}
	return r, nil
}

// Build serialises a single-view ISO/IEC 19794-2:2005 record.
//
// What Build can express is deliberately narrow:
//
//   - Finger position, impression type, quality and the minutiae are the
//     caller's; the remaining header fields are fixed constants.
//   - Resolution is 500 dpi, matching what pkg/biometrics/iso19794 writes.
//   - The capture device ID is left unreported (zero) and no certification
//     block is written.
//   - No extended data area is written. Emitting an empty length field is the
//     standard's way of saying "none", so this is conformant, but a record
//     carrying ridge counts or core/delta points cannot be reproduced here.
//
// Parse is the lossless direction; Build is the narrow one.
func Build(width, height int, fingerPosition, impressionType, quality uint8, minutiae []MinutiaFormat) ([]byte, error) {
	if width <= 0 || height <= 0 || width > 0xFFFF || height > 0xFFFF {
		return nil, fmt.Errorf("iso19794b: invalid dimensions %dx%d", width, height)
	}
	if fingerPosition > 10 {
		return nil, fmt.Errorf("%w: %d; the standard defines 0..10", ErrBadFingerPos, fingerPosition)
	}
	if impressionType != 0 && impressionType != 1 && impressionType != 2 && impressionType != 3 && impressionType != 8 {
		return nil, fmt.Errorf("%w: %d; the standard defines 0,1,2,3 and 8", ErrBadImpression, impressionType)
	}
	if quality > 100 {
		return nil, fmt.Errorf("%w: finger quality %d; the standard defines 0..100", ErrBadQuality, quality)
	}
	if len(minutiae) > maxMinutiae {
		return nil, fmt.Errorf("iso19794b: %d minutiae exceeds the one-byte count field", len(minutiae))
	}
	for i, m := range minutiae {
		// The standard defines 00 other, 01 ridge ending, 10 bifurcation and
		// leaves 11 reserved. A reserved value would not fail on re-read, it
		// would just match nothing.
		if m.Type > 2 {
			return nil, fmt.Errorf("iso19794b: minutia %d has type %d; only 0, 1 and 2 are defined", i, m.Type)
		}
		if m.X > maxCoord || m.Y > maxCoord {
			return nil, fmt.Errorf("iso19794b: minutia %d at (%d,%d) exceeds the 14-bit field", i, m.X, m.Y)
		}
		if m.Quality < 1 || m.Quality > 100 {
			return nil, fmt.Errorf("%w: minutia %d quality is %d; the standard defines 1..100", ErrBadQuality, i, m.Quality)
		}
	}

	extAreaLen := len(minutiae)*minutiaSize + FingerHeaderLen + extAreaLenSize
	out := make([]byte, RecordHeaderLen+extAreaLen)

	copy(out[0:4], formatIdentifier)
	copy(out[4:8], version2005)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(out)))
	out[12] = 0 // no certification block, capture device ID unreported
	out[13] = 0
	binary.BigEndian.PutUint16(out[14:16], uint16(width))
	binary.BigEndian.PutUint16(out[16:18], uint16(height))
	binary.BigEndian.PutUint16(out[18:20], 500) // X resolution, dpi
	binary.BigEndian.PutUint16(out[20:22], 500) // Y resolution, dpi
	out[22] = 1                                 // one finger view
	out[23] = 0                                 // reserved

	body := out[RecordHeaderLen:]
	body[0] = fingerPosition
	body[1] = 0<<4 | impressionType&0x0F // single view, so view number 0
	body[2] = quality
	body[3] = uint8(len(minutiae))

	off := FingerHeaderLen
	for i, m := range minutiae {
		e := body[off+i*minutiaSize : off+(i+1)*minutiaSize]
		// Type occupies the top 2 bits, X the low 14. The 2 bits above Y are
		// reserved and written as zero.
		binary.BigEndian.PutUint16(e[0:2], uint16(m.Type&0x03)<<14|m.X&0x3FFF)
		binary.BigEndian.PutUint16(e[2:4], m.Y&0x3FFF)
		e[4] = uint8(math.Round(normalizeAngle(m.Orientation) / angleUnits))
		e[5] = m.Quality
	}

	// Zero means "no extended data area", which is the standard's way of
	// saying the record ends here.
	binary.BigEndian.PutUint16(body[off+len(minutiae)*minutiaSize:], 0)
	return out, nil
}
