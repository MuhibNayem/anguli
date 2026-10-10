// Package cbeff implements the Common Biometric Exchange Formats Framework
// container defined by ISO/IEC 19785-1, the envelope that lets a fingerprint
// record from this system be read by a third-party PACS.
//
// Why this exists. The repository already reads and writes ISO/IEC 19794-2
// minutiae records and ISO/IEC 19794-4 images, both of which are Biometric
// Data Blocks (BDBs). A BDB on its own is not an interchange format: a
// receiver has no way to tell what the block contains. CBEFF supplies that,
// and it is what every vendor's enrollment system expects at the boundary. A
// system that stores proprietary records can read its own files; it cannot be
// enrolled from by anyone else.
//
// A Biometric Information Record (BIR) is three parts:
//
//	SBH - Standard Biometric Header, identifies the BDB that follows
//	BDB - the biometric data itself, format defined by ISO/IEC 19794-x
//	SB  - Security Block, optional, omitted here
//
// The SBH is a sequence of tag-length-value fields in a fixed order, with no
// separators; fields are located by counting bytes. All multi-byte values are
// big-endian.
//
// PROVENANCE. This package is written against the following sources, and the
// identifiers are asserted in the tests against values those sources state
// rather than against this encoder:
//
//	ISO/IEC 19785-1 (CBEFF data element specification) - the SBH tag numbers
//	  and the rule that format owner and format type are mandatory.
//	ISO/IEC 19785-3 Table 5 - the CBEFF_BDB_biometric_type abstract values,
//	  where Finger is 0x08. These are bit flags, not ordinals: Face 0x02,
//	  Voice 0x04, Finger 0x08, Iris 0x10.
//	ISO/IEC 19794-4 clause 6 - BDB_format_owner 0x0101, BDB_format_type 0x0007.
//	ISO/IEC 19794-2 Cor.1:2007 Table 16 - BDB_format_type 0x0001 for a
//	  minutiae record with no extended data, 0x0002 with extended data.
//	The CBEFF registry - owner 0x0101 is ISO/IEC JTC 1/SC 37, the committee
//	  that owns every ISO/IEC 19794-x BDB format.
//
// A caveat worth stating plainly: the standard permits additional optional
// fields this encoder does not write, and a third-party BIR may carry them.
// The decoder skips unknown tags rather than rejecting them, which is what the
// format intends, but it cannot interpret a field it has not been taught.
package cbeff

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SBH field tags. ISO/IEC 19785-1 assigns these; they are positions in the
// header, not arbitrary keys.
const (
	tagSecurityOptions byte = 0x00 // SBH security options, 1 byte
	tagPatronHeaderVer byte = 0x80 // CBEFF patron header version, 1 byte
	tagBiometricType   byte = 0x81 // BDB biometric type, 1 byte
	tagDBFormatOwner   byte = 0x87 // BDB format owner, 2 bytes  (mandatory)
	tagDBFormatType    byte = 0x88 // BDB format type, 2 bytes   (mandatory)
)

// CBEFF_BDB_biometric_type abstract values from ISO/IEC 19785-3 Table 5.
// These are independent bit flags; multiple can be OR'd together.
const (
	BiometricTypeMultiple  byte = 0x01
	BiometricTypeFace      byte = 0x02
	BiometricTypeVoice     byte = 0x04
	BiometricTypeFinger    byte = 0x08
	BiometricTypeIris      byte = 0x10
	BiometricTypeRetina    byte = 0x20
	BiometricTypeHandGeom  byte = 0x40
	BiometricTypeSignature byte = 0x80
)

// FormatOwnerJTC1SC37 is the CBEFF registration authority identifier for
// ISO/IEC JTC 1/SC 37 (257 decimal), the owner of every ISO/IEC 19794-x BDB
// format. It is the owner half of the owner/type pair.
const FormatOwnerJTC1SC37 uint16 = 0x0101

// BDB format types assigned by ISO/IEC JTC 1/SC 37 for the fingerprint record
// formats this repository implements.
const (
	// FormatTypeFingerMinutiae is ISO/IEC 19794-2, minutiae record with no
	// extended data (finger-minutiae-record-n).
	FormatTypeFingerMinutiae uint16 = 0x0001
	// FormatTypeFingerMinutiaeExt is ISO/IEC 19794-2, minutiae record with
	// extended data (finger-minutiae-record-x).
	FormatTypeFingerMinutiaeExt uint16 = 0x0002
	// FormatTypeFingerImage is ISO/IEC 19794-4, finger image record.
	FormatTypeFingerImage uint16 = 0x0007
)

// patronHeaderVersion is the version this implementation encodes as: major 1,
// minor 1.
const patronHeaderVersion byte = 0x02

// Security option values for the SBH security options field.
const (
	// SecurityPlain means the BDB carries no CBEFF-level encryption or
	// integrity. This is the default and is what a record wrapped by Wrap
	// contains; transport security is a separate concern handled by TLS.
	SecurityPlain byte = 0x00
)

var (
	// ErrTruncatedHeader means the buffer ended part-way through a field.
	ErrTruncatedHeader = errors.New("cbeff: header truncated")
	// ErrMissingMandatoryField means the SBH lacked format owner or format
	// type, which ISO/IEC 19785-1 makes mandatory. A record missing them
	// cannot be interpreted by anyone, so it is rejected rather than guessed.
	ErrMissingMandatoryField = errors.New("cbeff: mandatory header field missing")
	// ErrNoBDB means the header parsed but carried no biometric data block.
	ErrNoBDB = errors.New("cbeff: no biometric data block")
	// ErrEmptyBDB means Wrap was asked to build a record with no payload.
	ErrEmptyBDB = errors.New("cbeff: refusing to build a record with an empty data block")
)

// Header is the Standard Biometric Header.
//
// FormatOwner and FormatType are the pair that tells a receiver how to parse
// the BDB; BiometricType says what kind of biometric it is. Only the first two
// are mandatory.
type Header struct {
	SecurityOptions byte
	PatronHeaderVer byte
	BiometricType   byte
	FormatOwner     uint16
	FormatType      uint16
}

// FingerprintHeader returns the header for an ISO/IEC 19794-2 minutiae record
// with no extended data.
func FingerprintHeader() Header {
	return Header{
		SecurityOptions: SecurityPlain,
		PatronHeaderVer: patronHeaderVersion,
		BiometricType:   BiometricTypeFinger,
		FormatOwner:     FormatOwnerJTC1SC37,
		FormatType:      FormatTypeFingerMinutiae,
	}
}

// FingerprintImageHeader returns the header for an ISO/IEC 19794-4 image.
func FingerprintImageHeader() Header {
	h := FingerprintHeader()
	h.FormatType = FormatTypeFingerImage
	return h
}

// Wrap builds a BIR from a header and an already-encoded BDB.
//
// The BDB is passed through untouched. Whatever produced it - the 19794-2 or
// 19794-4 codec in this repository, or bytes from elsewhere - CBEFF's job is
// only to say what it is. That separation is deliberate: the container must
// never be the place a record goes wrong.
func Wrap(h Header, bdb []byte) ([]byte, error) {
	if len(bdb) == 0 {
		return nil, ErrEmptyBDB
	}

	// Security options and patron version: 1-byte tag, 1-byte length, value.
	out := make([]byte, 0, 8+len(bdb))
	out = append(out, tagSecurityOptions, 1, h.SecurityOptions)
	out = append(out, tagPatronHeaderVer, 1, h.PatronHeaderVer)
	out = append(out, tagBiometricType, 1, h.BiometricType)

	// Format owner and type: 2-byte values, still 1-byte tag and length.
	var two [2]byte
	binary.BigEndian.PutUint16(two[:], h.FormatOwner)
	out = append(out, tagDBFormatOwner, 2)
	out = append(out, two[:]...)

	binary.BigEndian.PutUint16(two[:], h.FormatType)
	out = append(out, tagDBFormatType, 2)
	out = append(out, two[:]...)

	return append(out, bdb...), nil
}

// Parse reads the SBH and returns it with the BDB that follows.
//
// Unknown tags are skipped rather than rejected. ISO/IEC 19785-1 allows
// patron formats to add optional fields, and a decoder that hard-failed on an
// unrecognised tag would refuse records from every vendor that uses one - which
// would defeat the purpose of having a standard container.
//
// The returned BDB aliases data, not a copy.
func Parse(data []byte) (Header, []byte, error) {
	var h Header
	var haveOwner, haveType bool

	// off is declared outside the loop because the BDB begins where the last
	// header field ended, and that position has to survive the loop.
	off := 0
	for off < len(data) {
		// The SBH has no overall length field. It ends once both mandatory
		// fields have been read, and everything from that offset to the end of
		// the buffer is the BDB. Checked at the top of the loop, before any
		// bytes are consumed: doing it after would advance the offset into the
		// payload and silently truncate the block.
		if haveOwner && haveType {
			break
		}
		if off+2 > len(data) {
			return h, nil, fmt.Errorf("%w at offset %d", ErrTruncatedHeader, off)
		}
		tag := data[off]
		length := int(data[off+1])
		off += 2

		if off+length > len(data) {
			return h, nil, fmt.Errorf("%w: tag 0x%02x at offset %d claims %d bytes",
				ErrTruncatedHeader, tag, off-2, length)
		}
		value := data[off : off+length]
		off += length

		switch tag {
		case tagSecurityOptions:
			if len(value) != 1 {
				return h, nil, fmt.Errorf("cbeff: security options must be 1 byte, got %d", len(value))
			}
			h.SecurityOptions = value[0]
		case tagPatronHeaderVer:
			if len(value) != 1 {
				return h, nil, fmt.Errorf("cbeff: patron header version must be 1 byte, got %d", len(value))
			}
			h.PatronHeaderVer = value[0]
		case tagBiometricType:
			if len(value) != 1 {
				return h, nil, fmt.Errorf("cbeff: biometric type must be 1 byte, got %d", len(value))
			}
			h.BiometricType = value[0]
		case tagDBFormatOwner:
			if len(value) != 2 {
				return h, nil, fmt.Errorf("cbeff: format owner must be 2 bytes, got %d", len(value))
			}
			h.FormatOwner = binary.BigEndian.Uint16(value)
			haveOwner = true
		case tagDBFormatType:
			if len(value) != 2 {
				return h, nil, fmt.Errorf("cbeff: format type must be 2 bytes, got %d", len(value))
			}
			h.FormatType = binary.BigEndian.Uint16(value)
			haveType = true
		default:
			// Optional patron-specific field: skipped by construction above.
		}
	}

	if !haveOwner || !haveType {
		return h, nil, fmt.Errorf("%w: owner=%t type=%t", ErrMissingMandatoryField, haveOwner, haveType)
	}

	bdb := data[off:]
	if len(bdb) == 0 {
		return h, nil, ErrNoBDB
	}
	return h, bdb, nil
}

// IsFingerprintMinutiae reports whether h identifies a 19794-2 minutiae
// record, in either the extended or non-extended form.
func (h Header) IsFingerprintMinutiae() bool {
	return h.FormatOwner == FormatOwnerJTC1SC37 &&
		(h.FormatType == FormatTypeFingerMinutiae || h.FormatType == FormatTypeFingerMinutiaeExt)
}

// IsFingerprintImage reports whether h identifies a 19794-4 image record.
func (h Header) IsFingerprintImage() bool {
	return h.FormatOwner == FormatOwnerJTC1SC37 && h.FormatType == FormatTypeFingerImage
}

// HasFingerType reports whether the biometric type flag includes Finger.
func (h Header) HasFingerType() bool { return h.BiometricType&BiometricTypeFinger != 0 }
