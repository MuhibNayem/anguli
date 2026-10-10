package cbeff

import (
	"encoding/hex"
	"testing"
	"time"
)

// The date test below uses the worked example printed in SP 800-76-2
// normative note 4. That example is the whole point of this file: it is a
// value the standard itself states, so it discriminates a correct encoder from
// an encoder that merely round-trips its own mistake. A round-trip test would
// pass if both halves encoded "2012" as the ASCII digits 0x32 0x30 0x31 0x32,
// which is not what the standard means.

// TestPIVDateMatchesTheStandardWorkedExample pins the date encoding against
// the standard's own numbers.
//
// SP 800-76-2 note 4: "17:35:30 December 15, 2005 is represented as:
// 00010100 00000101 00001100 00001111 00010001 00100011 00011110 01011010".
//
// Read as bytes: 14 05 0C 0F 11 23 1E 5A. Note these are NOT ASCII digits -
// the year 2005 is 0x14 0x05 because "20" is 20, not because '2' is 0x32.
// Only the trailing Z is an ASCII character, and 0x5A is 'Z'.
func TestPIVDateMatchesTheStandardWorkedExample(t *testing.T) {
	when := time.Date(2005, time.December, 15, 17, 35, 30, 0, time.UTC)

	got, err := encodePIVDate(when)
	if err != nil {
		t.Fatal(err)
	}

	const want = "14050c0f11231e5a"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("date encoded as %s, standard states %s", hex.EncodeToString(got[:]), want)
	}

	back, err := decodePIVDate(got[:])
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(when) {
		t.Fatalf("decoded %v, want %v", back, when)
	}
}

// TestPIVDateIsBinaryNotASCII is the negative form: it fails if someone
// "fixes" the encoder to write the ASCII digits, which is the obvious wrong
// implementation.
func TestPIVDateIsBinaryNotASCII(t *testing.T) {
	when := time.Date(2005, time.December, 15, 17, 35, 30, 0, time.UTC)
	got, _ := encodePIVDate(when)

	// '2' '0' '0' '5' as ASCII would start 0x32 0x30.
	if got[0] == 0x32 && got[1] == 0x30 {
		t.Fatal("date is encoded as ASCII digits; the standard codes each pair as a binary byte")
	}
	if got[7] != 'Z' {
		t.Fatalf("trailing byte 0x%02x, want ASCII 'Z' (0x5A)", got[7])
	}
}

// TestPIVHeaderFieldValuesMatchTable14 asserts the mandatory values the
// standard states, against the constants the encoder uses.
func TestPIVHeaderFieldValuesMatchTable14(t *testing.T) {
	// Table 14, field 1.
	if PIVPatronHeaderVersion != 0x03 {
		t.Errorf("patron header version 0x%02X, Table 14 states 0x03", PIVPatronHeaderVersion)
	}
	// Table 14 note 2, b00001101 for mandatory PIV Card elements.
	if PIVSecuritySignedNotEncrypted != 0x0D {
		t.Errorf("security options 0x%02X, note 2 states 0x0D", PIVSecuritySignedNotEncrypted)
	}
	if PIVSecuritySignedAndEncrypted != 0x0F {
		t.Errorf("signed+encrypted security options 0x%02X, note 2 states 0x0F", PIVSecuritySignedAndEncrypted)
	}

	// Table 15, fingerprint templates.
	if PIVFormatOwnerFingerprint != 0x001B {
		t.Errorf("fingerprint format owner 0x%04X, Table 15 states 0x001B (INCITS M1)", PIVFormatOwnerFingerprint)
	}
	if PIVFormatTypeFingerprintTemplate != 0x0201 {
		t.Errorf("template format type 0x%04X, Table 15 states 0x0201", PIVFormatTypeFingerprintTemplate)
	}
	if PIVFormatTypeFingerprintImage != 0x0401 {
		t.Errorf("image format type 0x%04X, Table 15 states 0x0401", PIVFormatTypeFingerprintImage)
	}
	if PIVBiometricTypeFinger != 0x000008 {
		t.Errorf("biometric type 0x%06X, Table 15 states 0x000008", PIVBiometricTypeFinger)
	}
	// Data type is a bitfield: processed is b100xxxxx, raw is b001xxxxx.
	if PIVDataTypeProcessed != 0x80 {
		t.Errorf("processed data type 0x%02X, Table 15 states b100xxxxx", PIVDataTypeProcessed)
	}
	if PIVDataTypeRaw != 0x20 {
		t.Errorf("raw data type 0x%02X, Table 15 states b001xxxxx", PIVDataTypeRaw)
	}

	// The field widths must sum to the documented 88 bytes, otherwise every
	// offset after the first disagreement is wrong.
	if 1+1+4+2+2+2+8+16+3+1+1+18+25+4 != PIVHeaderLen {
		t.Errorf("Table 14 field widths do not sum to the declared %d-byte header", PIVHeaderLen)
	}
}

// TestPIVFormatOwnerIsNotTheISOOwner guards the mistake this package is most
// likely to invite: reusing 0x0101 from the ISO/IEC 19794-x records instead of
// the 0x001B that Table 15 assigns to INCITS fingerprint data. The two are
// genuinely different owners and a PACS will reject the wrong one.
func TestPIVFormatOwnerIsNotTheISOOwner(t *testing.T) {
	if PIVFormatOwnerFingerprint == FormatOwnerJTC1SC37 {
		t.Fatal("PIV fingerprint owner must not be the ISO/IEC JTC 1 SC 37 owner")
	}
	if PIVFormatOwnerFingerprint == 0x001B && FormatOwnerJTC1SC37 == 0x0101 {
		// Correct as expected; assert both explicitly so the intent is visible.
		if PIVFormatOwnerFingerprint == FormatOwnerJTC1SC37 {
			t.Fatal("owners collide")
		}
	}
}

// TestPIVHeaderByteLayout checks the bytes at their specified offsets.
func TestPIVHeaderByteLayout(t *testing.T) {
	h := FingerprintTemplateHeader(1234, "ANGULI", 72, time.Date(2026, time.October, 10, 12, 0, 0, 0, time.UTC))
	b, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != PIVHeaderLen {
		t.Fatalf("header is %d bytes, Table 14 sums to %d", len(b), PIVHeaderLen)
	}

	if b[0] != 0x03 {
		t.Errorf("byte 0 = 0x%02X, want patron header version 0x03", b[0])
	}
	if b[1] != 0x0D {
		t.Errorf("byte 1 = 0x%02X, want security options 0x0D", b[1])
	}
	// BDB length is a 4-byte field at offset 2, big-endian per note 1.
	if b[2] != 0x00 || b[3] != 0x00 || b[4] != 0x04 || b[5] != 0xD2 {
		t.Errorf("BDB length bytes = % x, want 00 00 04 D2 (1234)", b[2:6])
	}
	// Owner 0x001B and type 0x0201.
	if b[8] != 0x00 || b[9] != 0x1B || b[10] != 0x02 || b[11] != 0x01 {
		t.Errorf("owner/type bytes = % x, want 00 1B 02 01", b[8:12])
	}
	// Creation date 2026-10-10 12:00:00Z. The year is 8 bytes total, encoded
	// as binary pairs: 20, 26, 10, 10, 12, 00, 00, then ASCII 'Z'.
	if got := hex.EncodeToString(b[12:20]); got != "141a0a0a0c00005a" {
		t.Errorf("creation date = %s, want 141a0a0a0c00005a", got)
	}
	// Biometric type 0x000008 over exactly three bytes.
	if b[36] != 0x00 || b[37] != 0x00 || b[38] != 0x08 {
		t.Errorf("biometric type bytes = % x, want 00 00 08", b[36:39])
	}
	if b[39] != PIVDataTypeProcessed {
		t.Errorf("data type = 0x%02X, want 0x80 (processed)", b[39])
	}
	if b[40] != 72 {
		t.Errorf("quality byte = %d, want 72", b[40])
	}
	if string(b[41:47]) != "ANGULI" || b[47] != 0 {
		t.Errorf("creator field = %q with terminator 0x%02X", b[41:48], b[47])
	}
	// Reserved must be zero.
	for i := 84; i < PIVHeaderLen; i++ {
		if b[i] != 0 {
			t.Errorf("reserved byte %d = 0x%02X, want 0", i, b[i])
		}
	}
}

func TestPIVHeaderRoundTrip(t *testing.T) {
	fascn := make([]byte, 25)
	for i := range fascn {
		fascn[i] = byte(i + 1)
	}
	in := FingerprintTemplateHeader(4242, "ANGULI-EDGE", -2, time.Date(2026, time.October, 10, 12, 0, 0, 0, time.UTC))
	in.FASCN = fascn

	b, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParsePIVHeader(b)
	if err != nil {
		t.Fatal(err)
	}

	if out.BDBLength != in.BDBLength {
		t.Errorf("BDB length %d != %d", out.BDBLength, in.BDBLength)
	}
	if out.FormatOwner != in.FormatOwner || out.FormatType != in.FormatType {
		t.Errorf("owner/type %04X/%04X != %04X/%04X", out.FormatOwner, out.FormatType, in.FormatOwner, in.FormatType)
	}
	if out.Quality != PIVQualityNotSupported {
		t.Errorf("quality %d, want -2 preserved through a signed byte", out.Quality)
	}
	if out.Creator != in.Creator {
		t.Errorf("creator %q != %q", out.Creator, in.Creator)
	}
	if !out.CreationDate.Equal(in.CreationDate) {
		t.Errorf("creation date %v != %v", out.CreationDate, in.CreationDate)
	}
	if len(out.FASCN) != 25 || out.FASCN[0] != 1 || out.FASCN[24] != 25 {
		t.Errorf("FASC-N not preserved: % x", out.FASCN)
	}
	if !out.IsFingerprintTemplate() {
		t.Error("header is not recognised as a fingerprint template")
	}
}

// TestPIVQualityIsSigned pins the signed-byte semantics. -2 means "quality
// assignment not supported"; stored in a uint8 it would read as 254, which is
// a plausible-looking value and completely wrong.
func TestPIVQualityIsSigned(t *testing.T) {
	for _, q := range []int8{-2, -1, 0, 50, 100} {
		h := FingerprintTemplateHeader(10, "A", q, time.Unix(0, 0).UTC())
		b, err := h.Encode()
		if err != nil {
			t.Fatalf("quality %d: %v", q, err)
		}
		got, err := ParsePIVHeader(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Quality != q {
			t.Errorf("quality %d round-tripped as %d", q, got.Quality)
		}
	}
	// Out of range on both sides.
	for _, q := range []int8{-3, 101, 127} {
		if _, err := (PIVHeader{Quality: q, FASCN: make([]byte, 25)}).Encode(); err == nil {
			t.Errorf("quality %d should be rejected", q)
		}
	}
}

func TestPIVHeaderRejectsMalformedFields(t *testing.T) {
	base := FingerprintTemplateHeader(10, "ANGULI", 50, time.Unix(0, 0).UTC())

	t.Run("short buffer", func(t *testing.T) {
		if _, err := ParsePIVHeader(make([]byte, 87)); err == nil {
			t.Fatal("expected an error for an 87-byte header")
		}
	})

	t.Run("fascn wrong length", func(t *testing.T) {
		h := base
		h.FASCN = make([]byte, 24)
		if _, err := h.Encode(); err == nil {
			t.Fatal("expected an error for a 24-byte FASC-N")
		}
		h.FASCN = make([]byte, 26)
		if _, err := h.Encode(); err == nil {
			t.Fatal("expected an error for a 26-byte FASC-N")
		}
	})

	t.Run("creator too long", func(t *testing.T) {
		h := base
		h.Creator = "123456789012345678" // 18 bytes
		if _, err := h.Encode(); err == nil {
			t.Fatal("expected an error for an 18-byte creator")
		}
		h.Creator = "12345678901234567" // exactly 17, the maximum
		if _, err := h.Encode(); err != nil {
			t.Fatalf("a 17-byte creator must be accepted: %v", err)
		}
	})

	t.Run("creator not printable", func(t *testing.T) {
		h := base
		h.Creator = "ANG\x00ULI"
		if _, err := h.Encode(); err == nil {
			t.Fatal("expected an error for a non-printable creator")
		}
	})

	t.Run("year out of range", func(t *testing.T) {
		h := base
		h.CreationDate = time.Date(12026, time.January, 1, 0, 0, 0, 0, time.UTC)
		if _, err := h.Encode(); err == nil {
			t.Fatal("expected an error for a 5-digit year")
		}
	})
}

// TestPIVBiometricTypeUsesThreeBytes: Table 15 gives biometric type as a
// 3-byte quantity inside a 4-byte slot. Reading four bytes would fold the
// data-type byte into the value and produce 0x00000880 instead of 0x000008.
func TestPIVBiometricTypeUsesThreeBytes(t *testing.T) {
	h := FingerprintTemplateHeader(10, "A", 50, time.Unix(0, 0).UTC())
	b, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got := uint32(b[36])<<16 | uint32(b[37])<<8 | uint32(b[38]); got != PIVBiometricTypeFinger {
		t.Fatalf("biometric type 0x%06X, want 0x000008", got)
	}
	if b[39] != PIVDataTypeProcessed {
		t.Fatalf("data type byte 0x%02X, want 0x80", b[39])
	}
}
