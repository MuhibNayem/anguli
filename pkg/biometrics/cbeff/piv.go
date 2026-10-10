package cbeff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// PIV patron format (NIST SP 800-76-2, Table 14).
//
// The generic SBH in cbeff.go identifies a BDB and stops. PIV needs more: it
// is the patron format US federal PIV cards use, and it carries a fixed,
// fully mandatory 88-byte header with explicit BDB and signature-block
// lengths, a signed quality value and a FASC-N cardholder identifier.
//
// Implementing it here rather than as a separate package keeps the CBEFF
// vocabulary - format owner, format type, biometric type - in one place.
//
// PROVENANCE. Every constant below is transcribed from NIST SP 800-76-2,
// which is freely published:
//
//	Table 14 - the 14 header fields, their lengths and required values
//	Table 15 - modality-specific values; fingerprint templates
//	Normative Note 1  - big-endian
//	Normative Note 2  - security options bitfield
//	Normative Note 4  - creation date encoding, with a worked example
//	Normative Note 6  - creator field encoding
//
// What is NOT implemented: the CBEFF_SIGNATURE_BLOCK itself. SP 800-76-2
// 9.3 requires a CMS external signature (RFC 5652) computed over the header
// concatenated with the biometric record, with a documented two-phase
// computation because the signature length feeds back into the header. That
// needs a certificate and is out of scope here. A record produced by this
// package therefore declares a security-options bitfield that claims a
// signature, so callers must either sign it or overwrite that field - see
// SecurityOptions and the note on PIVSecuritySignedNotEncrypted.

const (
	// PIVHeaderLen is the fixed size of the PIV CBEFF header:
	// 1+1+4+2+2+2+8+16+3+1+1+18+25+4 = 88 bytes.
	PIVHeaderLen = 88

	// PIVPatronHeaderVersion is the required value (Table 14, field 1).
	PIVPatronHeaderVersion byte = 0x03

	// PIVSecuritySignedNotEncrypted is b00001101, the mandatory value for the
	// mandatory MINUSTD elements on a PIV Card (Table 14 note 2).
	//
	// Bit layout: 0x08 is set per prior versions of the document; 0x04
	// implements the CBEFF requirement that a digital signature be
	// distinguished from a MAC; 0x02 indicates encryption; 0x01 indicates a
	// digital signature.
	PIVSecuritySignedNotEncrypted byte = 0x0D

	// PIVSecuritySignedAndEncrypted is b00001111.
	PIVSecuritySignedAndEncrypted byte = 0x0F
)

// Modality values for fingerprint data from Table 15. Note the format owner
// here is 0x001B (INCITS Technical Committee M1 on Biometrics), NOT the
// 0x0101 (ISO/IEC JTC 1/SC 37) used by the ISO/IEC 19794-x records this
// repository also produces. Getting that wrong produces a header a PACS
// rejects, and it is the single most likely mistake when wiring this up.
const (
	PIVFormatOwnerFingerprint uint16 = 0x001B

	// PIVFormatTypeFingerprintTemplate is INCITS 378-2004 minutiae, the
	// format PIV card templates use.
	PIVFormatTypeFingerprintTemplate uint16 = 0x0201
	// PIVFormatTypeFingerprintImage is INCITS 381 finger image.
	PIVFormatTypeFingerprintImage uint16 = 0x0401

	// PIVBiometricTypeFinger is the 3-byte value 0x000008.
	PIVBiometricTypeFinger uint32 = 0x000008

	// PIVDataTypeProcessed is b100xxxxx: a template, i.e. data that has
	// already been through minutiae extraction.
	PIVDataTypeProcessed byte = 0x80
	// PIVDataTypeRaw is b001xxxxx: an image.
	PIVDataTypeRaw byte = 0x20
)

// PIVQuality bounds. Table 14 field 11 defines quality as a SIGNED byte:
// -2 means quality assignment is not supported, -1 means the attempt failed,
// and 0..100 indicate increasing confidence. Storing -2 in a uint8 would
// read as 254, which the standard uses for a different meaning entirely.
const (
	PIVQualityNotSupported int8 = -2
	PIVQualityFailed       int8 = -1
	PIVQualityMax               = 100
	PIVQualityMin               = -2
)

var (
	// ErrPIVHeaderShort means fewer than 88 bytes were supplied.
	ErrPIVHeaderShort = errors.New("cbeff: PIV header must be 88 bytes")
	// ErrPIVQualityRange means quality fell outside -2..100.
	ErrPIVQualityRange = errors.New("cbeff: PIV quality must be between -2 and 100")
	// ErrPIVCreatorTooLong means the creator exceeded the 17 usable bytes.
	ErrPIVCreatorTooLong = errors.New("cbeff: PIV creator must be at most 17 bytes")
	// ErrPIVFASCNLength means FASC-N was not exactly 25 bytes.
	ErrPIVFASCNLength = errors.New("cbeff: PIV FASC-N must be exactly 25 bytes")
	// ErrPIVDateOutOfRange means a date could not be represented.
	ErrPIVDateOutOfRange = errors.New("cbeff: date outside the representable PIV range")
)

// PIVHeader is the 88-byte PIV patron format CBEFF header.
//
// Field numbers correspond to Table 14.
type PIVHeader struct {
	SecurityOptions byte      // field 2
	BDBLength       uint32    // field 3
	SBLength        uint16    // field 4
	FormatOwner     uint16    // field 5
	FormatType      uint16    // field 6
	CreationDate    time.Time // field 7
	ValidityStart   time.Time // field 8a
	ValidityEnd     time.Time // field 8b
	BiometricType   uint32    // field 9
	DataType        byte      // field 10
	Quality         int8      // field 11
	Creator         string    // field 12
	FASCN           []byte    // field 13, exactly 25 bytes
}

// FingerprintTemplateHeader returns a header for an INCITS 378 minutiae
// template with the mandatory PIV values applied.
func FingerprintTemplateHeader(bdbLen int, creator string, quality int8, now time.Time) PIVHeader {
	return PIVHeader{
		SecurityOptions: PIVSecuritySignedNotEncrypted,
		BDBLength:       uint32(bdbLen),
		SBLength:        0,
		FormatOwner:     PIVFormatOwnerFingerprint,
		FormatType:      PIVFormatTypeFingerprintTemplate,
		CreationDate:    now.UTC(),
		ValidityStart:   now.UTC(),
		ValidityEnd:     now.UTC().AddDate(8, 0, 0),
		BiometricType:   PIVBiometricTypeFinger,
		DataType:        PIVDataTypeProcessed,
		Quality:         quality,
		Creator:         creator,
		FASCN:           make([]byte, 25),
	}
}

// encodePIVDate renders a time as the 8-byte binary "YYYYMMDDhhmmssZ".
//
// SP 800-76-2 normative note 4: each pair of characters is coded as a
// binary unsigned byte, so the year 2005 is 0x14 0x05, not the ASCII digits.
// The trailing 'Z' is the ASCII character, indicating UTC.
//
// Fields are individually masked to their legal width rather than range
// checked as a whole, because the standard encodes what it is given into a
// fixed 8-byte shape. Month 13 would silently become 1; callers should
// validate real dates rather than rely on this to.
func encodePIVDate(t time.Time) ([8]byte, error) {
	u := t.UTC()
	var b [8]byte
	year := u.Year()
	if year < 0 || year > 9999 {
		return b, fmt.Errorf("%w: year %d", ErrPIVDateOutOfRange, year)
	}
	b[0] = byte(year / 100)
	b[1] = byte(year % 100)
	b[2] = byte(u.Month())
	b[3] = byte(u.Day())
	b[4] = byte(u.Hour())
	b[5] = byte(u.Minute())
	b[6] = byte(u.Second())
	b[7] = 'Z' // ASCII 0x5A
	return b, nil
}

// decodePIVDate is the inverse of encodePIVDate.
func decodePIVDate(b []byte) (time.Time, error) {
	if len(b) != 8 {
		return time.Time{}, fmt.Errorf("cbeff: PIV date field is %d bytes, want 8", len(b))
	}
	return time.Date(
		int(b[0])*100+int(b[1]),
		time.Month(b[2]), int(b[3]), int(b[4]), int(b[5]), int(b[6]),
		0, time.UTC,
	), nil
}

// Encode renders the header as exactly 88 bytes.
func (h PIVHeader) Encode() ([]byte, error) {
	if h.Quality < PIVQualityMin || h.Quality > PIVQualityMax {
		return nil, fmt.Errorf("%w: got %d", ErrPIVQualityRange, h.Quality)
	}
	if len(h.Creator) > 17 {
		return nil, fmt.Errorf("%w: got %d", ErrPIVCreatorTooLong, len(h.Creator))
	}
	for i := 0; i < len(h.Creator); i++ {
		if h.Creator[i] < 0x20 || h.Creator[i] > 0x7E {
			return nil, fmt.Errorf("cbeff: PIV creator must be printable ASCII, got byte 0x%02x at %d", h.Creator[i], i)
		}
	}
	if len(h.FASCN) != 25 {
		return nil, fmt.Errorf("%w: got %d", ErrPIVFASCNLength, len(h.FASCN))
	}

	created, err := encodePIVDate(h.CreationDate)
	if err != nil {
		return nil, err
	}
	start, err := encodePIVDate(h.ValidityStart)
	if err != nil {
		return nil, err
	}
	end, err := encodePIVDate(h.ValidityEnd)
	if err != nil {
		return nil, err
	}

	out := make([]byte, PIVHeaderLen)

	out[0] = PIVPatronHeaderVersion                      // field 1
	out[1] = h.SecurityOptions                           // field 2
	binary.BigEndian.PutUint32(out[2:6], h.BDBLength)    // field 3
	binary.BigEndian.PutUint16(out[6:8], h.SBLength)     // field 4
	binary.BigEndian.PutUint16(out[8:10], h.FormatOwner) // field 5
	binary.BigEndian.PutUint16(out[10:12], h.FormatType) // field 6
	copy(out[12:20], created[:])                         // field 7
	copy(out[20:28], start[:])                           // field 8a
	copy(out[28:36], end[:])                             // field 8b
	// field 9: biometric type is a 3-byte quantity inside a 4-byte slot.
	// PutUint32 needs four bytes, so writing it directly would either panic
	// on the slot width or silently pull in the following data-type byte.
	out[36] = byte(h.BiometricType >> 16)
	out[37] = byte(h.BiometricType >> 8)
	out[38] = byte(h.BiometricType)
	out[39] = h.DataType      // field 10
	out[40] = byte(h.Quality) // field 11, SINT

	// field 12: printable ASCII then a null terminator, zero-filled after.
	copy(out[41:59], h.Creator)

	// field 13: FASC-N, exactly 25 bytes.
	copy(out[59:84], h.FASCN)

	// field 14: reserved, zero.
	binary.BigEndian.PutUint32(out[84:88], 0)

	return out, nil
}

// ParsePIVHeader decodes an 88-byte PIV CBEFF header.
func ParsePIVHeader(b []byte) (PIVHeader, error) {
	var h PIVHeader
	if len(b) < PIVHeaderLen {
		return h, fmt.Errorf("%w: got %d", ErrPIVHeaderShort, len(b))
	}

	h.SecurityOptions = b[1]
	h.BDBLength = binary.BigEndian.Uint32(b[2:6])
	h.SBLength = binary.BigEndian.Uint16(b[6:8])
	h.FormatOwner = binary.BigEndian.Uint16(b[8:10])
	h.FormatType = binary.BigEndian.Uint16(b[10:12])

	var err error
	if h.CreationDate, err = decodePIVDate(b[12:20]); err != nil {
		return h, err
	}
	if h.ValidityStart, err = decodePIVDate(b[20:28]); err != nil {
		return h, err
	}
	if h.ValidityEnd, err = decodePIVDate(b[28:36]); err != nil {
		return h, err
	}

	// The trailing byte is part of the 4-byte slot but is not part of the
	// value: Table 15 gives biometric types as 3 bytes.
	h.BiometricType = uint32(b[36])<<16 | uint32(b[37])<<8 | uint32(b[38])
	h.DataType = b[39]
	h.Quality = int8(b[40])

	creator := b[41:59]
	if i := indexByte(creator, 0); i >= 0 {
		creator = creator[:i]
	}
	h.Creator = string(creator)

	h.FASCN = append([]byte(nil), b[59:84]...)
	return h, nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// IsFingerprintTemplate reports whether the header identifies an INCITS 378
// minutiae template.
func (h PIVHeader) IsFingerprintTemplate() bool {
	return h.FormatOwner == PIVFormatOwnerFingerprint &&
		h.FormatType == PIVFormatTypeFingerprintTemplate
}
