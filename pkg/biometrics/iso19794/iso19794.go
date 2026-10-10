// Package iso19794 reads ISO/IEC 19794-4 fingerprint image records.
//
// Why this exists: the platform's native format is a raw greyscale buffer, so
// without a reader for the interchange standard no existing fingerprint
// database can be imported and no certified reader can hand over a compliant
// image. This package parses the record header defined by ISO/IEC 19794-4:2009
// section 5.3 and extracts the pixel data, which is what the enrollment
// pipeline actually needs.
//
// Scope is deliberate. This handles the fixed-length record header and the
// image payload, and it validates rather than assumes: every length, size and
// field is checked against the declared values before a single byte is
// trusted. It does not implement compression beyond the uncompressed case,
// which is what the pipeline consumes today.
package iso19794

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RecordHeaderLen is the fixed length of an ISO/IEC 19794-4 record header,
// in bytes (section 5.3.1). Everything after this is record-type specific.
const RecordHeaderLen = 24

var (
	// ErrTooShort means the buffer cannot hold even a record header.
	ErrTooShort = errors.New("iso19794: record shorter than the 24-byte header")

	// ErrBadMagic means the record does not carry the format identifier.
	ErrBadMagic = errors.New("iso19794: record is not an ISO/IEC 19794-4 image record")

	// ErrBadVersion means the record version is not supported.
	ErrBadVersion = errors.New("iso19794: unsupported record version")

	// ErrRecordLengthMismatch means the declared record length disagrees with
	// the data supplied. Truncating or padding here would silently corrupt a
	// biometric template, so it is an error.
	ErrRecordLengthMismatch = errors.New("iso19794: declared record length does not match the data")

	// ErrInconsistentDimensions means the header, resolution and image record
	// fields disagree about the image size.
	ErrInconsistentDimensions = errors.New("iso19794: dimensions in the header and image record disagree")

	// ErrUnsupportedResolution means a resolution the pipeline cannot map to
	// pixels. 19794 stores dots-per-inch; we need samples per pixel.
	ErrUnsupportedResolution = errors.New("iso19794: unsupported resolution")
)

// Format identifiers from ISO/IEC 19794-4. The low byte of the 4-byte format
// field identifies the record; the rest is reserved and must be zero.
const (
	formatFingerRecord uint32 = 0x00000001
	formatImageRecord  uint32 = 0x00000002
	formatMinutiaeData uint32 = 0x00000003
)

// ImageRepresentation identifies how the samples are encoded.
type ImageRepresentation byte

const (
	// Rep8BitLinear is an 8-bit linear greyscale image, the representation the
	// enrollment pipeline consumes.
	Rep8BitLinear ImageRepresentation = 0x01
	// Rep8BitNonLinear is an 8-bit non-linear greyscale image.
	Rep8BitNonLinear ImageRepresentation = 0x02
)

// supportedResolutions are the scanning resolutions this pipeline accepts,
// in dots per inch. 1000 dpi is the practical ceiling for live-scan hardware;
// accepting a larger declared resolution without honouring it would silently
// rescale the geometry the matcher depends on.
var supportedResolutions = map[uint16]bool{500: true, 600: true, 1000: true}

// Header is the parsed fixed-length record header.
type Header struct {
	Format    uint32
	Version   uint32
	RecordLen uint32

	// DataBlockHeight and DataBlockWidth are the image dimensions in pixels.
	DataBlockHeight uint16
	DataBlockWidth  uint16
	ResolutionUnits uint8 // 0 = pixels per inch, 1 = pixels per cm
	ResolutionX     uint16
	ResolutionY     uint16
	NumImages       uint8
	SubjectCount    uint8
	FingerQuality   uint8
}

// ImageRecord is a fully parsed finger image.
type ImageRecord struct {
	Header         Header
	Representation ImageRepresentation
	Width          int
	Height         int
	// Pixels holds Width*Height samples in row-major order.
	Pixels []uint8
	// SubjectCount is the number of subjects in the record. Live-scan records
	// carry exactly one; anything higher is a multi-finger record we must not
	// silently treat as a single enrollment.
	SubjectCount    uint16
	SubjectPosition uint8
}

// DPIPerPixel returns the horizontal sampling density in dots per inch,
// converting from pixels-per-centimetre when the record says so.
func (h Header) DPIPerPixel() (float64, error) {
	switch h.ResolutionUnits {
	case 0:
		return float64(h.ResolutionX), nil
	case 1:
		return float64(h.ResolutionX) * 2.54, nil
	default:
		return 0, ErrUnsupportedResolution
	}
}

// ParseHeader reads the fixed-length record header.
//
// Offsets follow ISO/IEC 19794-4:2009 table 4:
//
//	[0:4]   format               uint32
//	[4:8]   version              uint32
//	[8:12]  record length        uint32
//	[12:14] data block height    uint16
//	[14:16] data block width     uint16
//	[16]    resolution units     uint8   (0 = dpi, 1 = dpcm)
//	[17:19] resolution x         uint16
//	[19:21] resolution y         uint16
//	[21]    number of images     uint8
//	[22]    subject count        uint8
//	[23]    finger quality       uint8
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < RecordHeaderLen {
		return h, fmt.Errorf("%w: got %d bytes", ErrTooShort, len(b))
	}

	h.Format = binary.BigEndian.Uint32(b[0:4])
	h.Version = binary.BigEndian.Uint32(b[4:8])
	h.RecordLen = binary.BigEndian.Uint32(b[8:12])
	h.DataBlockHeight = binary.BigEndian.Uint16(b[12:14])
	h.DataBlockWidth = binary.BigEndian.Uint16(b[14:16])
	h.ResolutionUnits = b[16]
	h.ResolutionX = binary.BigEndian.Uint16(b[17:19])
	h.ResolutionY = binary.BigEndian.Uint16(b[19:21])
	h.NumImages = b[21]
	h.SubjectCount = b[22]
	h.FingerQuality = b[23]
	return h, nil
}

// IsFingerImageRecord reports whether the format field names a finger image
// record.
func IsFingerImageRecord(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(b[0:4]) == formatImageRecord
}

// ParseImage decodes a complete ISO/IEC 19794-4 finger image record.
//
// The returned pixels are the raw samples the enrollment pipeline expects, so
// an imported database and a live reader feed the same matcher.
func ParseImage(b []byte) (*ImageRecord, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}

	if h.Format != formatImageRecord {
		return nil, fmt.Errorf("%w: format = 0x%08X", ErrBadMagic, h.Format)
	}
	if h.Version != 0x00300000 {
		return nil, fmt.Errorf("%w: version = 0x%08X", ErrBadVersion, h.Version)
	}
	if h.NumImages != 1 {
		// A multi-image record cannot be mapped onto one enrollment without
		// deciding which capture to trust, which is a policy question rather
		// than a decoding one.
		return nil, fmt.Errorf("iso19794: expected exactly one image, record declares %d", h.NumImages)
	}
	if h.DataBlockWidth == 0 || h.DataBlockHeight == 0 {
		return nil, fmt.Errorf("%w: %dx%d", ErrInconsistentDimensions, h.DataBlockWidth, h.DataBlockHeight)
	}

	dpi, err := h.DPIPerPixel()
	if err != nil {
		return nil, err
	}
	if !supportedResolutions[uint16(dpi)] {
		return nil, fmt.Errorf("%w: %.0f dpi", ErrUnsupportedResolution, dpi)
	}

	// The image record proper begins immediately after the fixed header.
	if len(b) < RecordHeaderLen+5 {
		return nil, fmt.Errorf("%w: image record body truncated", ErrTooShort)
	}
	body := b[RecordHeaderLen:]
	rep := ImageRepresentation(body[0])
	if rep != Rep8BitLinear && rep != Rep8BitNonLinear {
		return nil, fmt.Errorf("iso19794: unsupported image representation 0x%02X", byte(rep))
	}

	// Record length is authoritative; a mismatch means truncated or padded data
	// and must not be silently tolerated.
	if int(h.RecordLen) != len(b) {
		return nil, fmt.Errorf("%w: header declares %d, got %d",
			ErrRecordLengthMismatch, h.RecordLen, len(b))
	}

	// The image record carries its own width, height and resolution, which
	// must agree with the record header.
	imgW := binary.BigEndian.Uint16(body[1:3])
	imgH := binary.BigEndian.Uint16(body[3:5])
	if imgW != h.DataBlockWidth || imgH != h.DataBlockHeight {
		return nil, fmt.Errorf("%w: header %dx%d vs image %dx%d",
			ErrInconsistentDimensions, h.DataBlockWidth, h.DataBlockHeight, imgW, imgH)
	}

	// Image record body layout, immediately after the 24-byte record header:
	//   [0]    image representation          1 byte
	//   [1:3]  image width                   2 bytes
	//   [3:5]  image height                  2 bytes
	//   [5]    reserved                      1 byte
	//   [6:8]  finger quality                2 bytes
	//   [8]    number of subjects in image   1 byte
	//   [9:11] subject count                 2 bytes
	//   [11:]  image samples
	const fixedBodyLen = 11
	const subjectCountOff = 9
	if len(body) < fixedBodyLen {
		return nil, fmt.Errorf("%w: image record body truncated", ErrTooShort)
	}
	subjectCount := binary.BigEndian.Uint16(body[subjectCountOff : subjectCountOff+2])
	if subjectCount != 1 {
		return nil, fmt.Errorf("iso19794: expected one subject, record declares %d", subjectCount)
	}

	pixels := body[fixedBodyLen:]
	want := int(imgW) * int(imgH)
	if len(pixels) < want {
		return nil, fmt.Errorf("%w: image declares %dx%d (%d samples) but only %d are present",
			ErrInconsistentDimensions, imgW, imgH, want, len(pixels))
	}

	out := make([]uint8, want)
	copy(out, pixels[:want])

	return &ImageRecord{
		Header:         h,
		Representation: rep,
		Width:          int(imgW),
		Height:         int(imgH),
		Pixels:         out,
		SubjectCount:   subjectCount,
	}, nil
}

// BuildImage serialises a greyscale image as a single-subject ISO/IEC
// 19794-4 finger image record.
//
// This is the write direction: it lets the platform EXPORT in the standard
// form, which is what a certified reader or an external system expects to
// consume. Round-tripping through BuildImage and ParseImage is lossless.
func BuildImage(pixels []uint8, width, height int, dpi uint16) ([]byte, error) {
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("iso19794: invalid dimensions %dx%d", width, height)
	}
	if len(pixels) < width*height {
		return nil, fmt.Errorf("iso19794: %d samples for a %dx%d image", len(pixels), width, height)
	}
	if !supportedResolutions[dpi] {
		return nil, fmt.Errorf("%w: %d dpi", ErrUnsupportedResolution, dpi)
	}
	if width > 0xFFFF || height > 0xFFFF {
		return nil, fmt.Errorf("iso19794: %dx%d exceeds the 16-bit dimension fields", width, height)
	}

	const fixedBodyLen = 11
	total := RecordHeaderLen + fixedBodyLen + width*height

	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], formatImageRecord)
	binary.BigEndian.PutUint32(out[4:8], 0x00300000)
	binary.BigEndian.PutUint32(out[8:12], uint32(total))
	binary.BigEndian.PutUint16(out[12:14], uint16(height))
	binary.BigEndian.PutUint16(out[14:16], uint16(width))
	out[16] = 0 // resolution units: pixels per inch
	binary.BigEndian.PutUint16(out[17:19], dpi)
	binary.BigEndian.PutUint16(out[19:21], dpi)
	out[21] = 1 // one image
	out[22] = 1 // one subject
	out[23] = 0 // finger quality

	body := out[RecordHeaderLen:]
	body[0] = byte(Rep8BitLinear)
	binary.BigEndian.PutUint16(body[1:3], uint16(width))
	binary.BigEndian.PutUint16(body[3:5], uint16(height))
	body[5] = 0                               // reserved
	body[6] = 0                               // finger quality, high byte
	body[7] = 0                               // finger quality, low byte
	body[8] = 1                               // one subject in the image
	binary.BigEndian.PutUint16(body[9:11], 1) // one subject
	copy(body[fixedBodyLen:], pixels[:width*height])

	return out, nil
}
