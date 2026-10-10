package cbeff

import (
	"encoding/binary"
	"errors"
	"testing"

	"finger-scanner/pkg/biometrics/iso19794b"
)

// The assertions below are deliberately written against values the standard
// states, not against values this encoder produces. A round-trip test would
// pass even if the tag numbers and identifiers were wrong in a matching pair,
// which is the failure mode that matters most here: a container that
// self-consistently encodes the wrong thing is worse than no container, because
// it looks like interoperability and is not.

func TestSpecStatedIdentifiers(t *testing.T) {
	// ISO/IEC 19785-3 Table 5 lists the biometric types as independent bit
	// flags. Finger is 0x08, sitting between Voice 0x04 and Iris 0x10.
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"Face", BiometricTypeFace, 0x02},
		{"Voice", BiometricTypeVoice, 0x04},
		{"Finger", BiometricTypeFinger, 0x08},
		{"Iris", BiometricTypeIris, 0x10},
		{"Retina", BiometricTypeRetina, 0x20},
		{"HandGeometry", BiometricTypeHandGeom, 0x40},
		{"Signature", BiometricTypeSignature, 0x80},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got 0x%02x, standard states 0x%02x", c.name, c.got, c.want)
		}
	}

	// Owner 0x0101 is ISO/IEC JTC 1/SC 37 (257 decimal), the owner of every
	// ISO/IEC 19794-x BDB format.
	if FormatOwnerJTC1SC37 != 0x0101 {
		t.Errorf("format owner: got 0x%04x, standard states 0x0101", FormatOwnerJTC1SC37)
	}

	// Format types as assigned by SC 37.
	for _, c := range []struct {
		name string
		got  uint16
		want uint16
	}{
		{"finger-minutiae-record-n", FormatTypeFingerMinutiae, 0x0001},
		{"finger-minutiae-record-x", FormatTypeFingerMinutiaeExt, 0x0002},
		{"finger image record", FormatTypeFingerImage, 0x0007},
	} {
		if c.got != c.want {
			t.Errorf("%s: got 0x%04x, standard states 0x%04x", c.name, c.got, c.want)
		}
	}
}

// TestWrappedHeaderByteLayout checks the bytes on the wire, tag by tag, against
// the field order ISO/IEC 19785-1 defines. Encoding the wrong tag, or the right
// tags in the wrong order, produces a file no reader accepts and no round-trip
// test would catch.
func TestWrappedHeaderByteLayout(t *testing.T) {
	h := FingerprintHeader()
	rec, err := Wrap(h, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err != nil {
		t.Fatal(err)
	}

	// security options, patron version, biometric type, owner, type = 3+3+3+4+4 = 17 bytes of SBH.
	if len(rec) != 17+4 {
		t.Fatalf("record is %d bytes, expected a 17-byte header plus a 4-byte BDB", len(rec))
	}

	want := []byte{
		0x00, 0x01, 0x00, // security options
		0x80, 0x01, 0x02, // patron header version
		0x81, 0x01, 0x08, // biometric type = Finger
		0x87, 0x02, 0x01, 0x01, // format owner = 0x0101
		0x88, 0x02, 0x00, 0x01, // format type = 0x0001
		0xDE, 0xAD, 0xBE, 0xEF, // BDB
	}
	for i := range want {
		if rec[i] != want[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x (full record %x)", i, rec[i], want[i], rec)
		}
	}
}

func TestParseRecognisesFingerprintMinutiae(t *testing.T) {
	rec, err := Wrap(FingerprintHeader(), []byte("minutiae-payload"))
	if err != nil {
		t.Fatal(err)
	}
	h, bdb, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !h.HasFingerType() {
		t.Error("biometric type does not carry the Finger flag")
	}
	if !h.IsFingerprintMinutiae() {
		t.Error("header is not recognised as a 19794-2 minutiae record")
	}
	if h.IsFingerprintImage() {
		t.Error("a minutiae record must not be recognised as a 19794-4 image")
	}
	if string(bdb) != "minutiae-payload" {
		t.Errorf("BDB = %q, want the payload unchanged", bdb)
	}
}

func TestParseRecognisesFingerprintImage(t *testing.T) {
	rec, err := Wrap(FingerprintImageHeader(), []byte("image-payload"))
	if err != nil {
		t.Fatal(err)
	}
	h, bdb, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !h.IsFingerprintImage() {
		t.Error("header is not recognised as a 19794-4 image record")
	}
	if string(bdb) != "image-payload" {
		t.Errorf("BDB = %q", bdb)
	}
}

// TestParseSkipsUnknownTags: patron formats may add optional fields, and a
// decoder that rejected them would refuse every third-party BIR that uses one.
func TestParseSkipsUnknownTags(t *testing.T) {
	base, err := Wrap(FingerprintHeader(), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Insert an unknown optional field right after the first field.
	unknown := []byte{0x3A, 0x02, 0xAB, 0xCD}
	rec := append(append([]byte{}, base[:3]...), unknown...)
	rec = append(rec, base[3:]...)

	h, bdb, err := Parse(rec)
	if err != nil {
		t.Fatalf("an unknown optional tag must be skipped, not rejected: %v", err)
	}
	if !h.IsFingerprintMinutiae() {
		t.Error("header lost its identity after skipping the unknown field")
	}
	if string(bdb) != "payload" {
		t.Errorf("BDB = %q", bdb)
	}
}

// TestParseRejectsMissingMandatoryFields: format owner and type are what make
// a BDB interpretable, so a record without them is useless rather than merely
// incomplete.
func TestParseRejectsMissingMandatoryFields(t *testing.T) {
	h := FingerprintHeader()
	full, err := Wrap(h, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	// The three optional fields only, and nothing after them. There is no BDB
	// to reinterpret as header bytes, so the parse ends with the mandatory
	// fields still absent.
	noOwnerType := []byte{
		0x00, 0x01, 0x00,
		0x80, 0x01, 0x02,
		0x81, 0x01, 0x08,
	}
	if _, _, err := Parse(noOwnerType); !errors.Is(err, ErrMissingMandatoryField) {
		t.Errorf("missing owner/type: got %v, want ErrMissingMandatoryField", err)
	}
	if len(full) == 0 {
		t.Fatal("sanity: full record should not be empty")
	}
}

func TestParseRejectsTruncatedRecords(t *testing.T) {
	full, err := Wrap(FingerprintHeader(), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Only truncations that cut into the 17-byte header are necessarily
	// invalid. Cutting the 7-byte BDB short still leaves a well-formed record
	// carrying a shorter block, which is legal - so asserting on every prefix
	// would be asserting something the format does not promise.
	for n := 1; n < 17; n++ {
		if _, _, err := Parse(full[:n]); err == nil {
			t.Fatalf("header truncated to %d bytes parsed without error", n)
		}
	}
}

func TestParseRejectsEmptyBDB(t *testing.T) {
	hdr, err := Wrap(FingerprintHeader(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Parse(hdr[:len(hdr)-1]); !errors.Is(err, ErrNoBDB) {
		t.Errorf("got %v, want ErrNoBDB", err)
	}
}

func TestWrapRefusesEmptyBDB(t *testing.T) {
	if _, err := Wrap(FingerprintHeader(), nil); !errors.Is(err, ErrEmptyBDB) {
		t.Errorf("got %v, want ErrEmptyBDB", err)
	}
}

// TestWrapRealMinutiaeRecord is the end-to-end check that matters: a record
// this repository's own 19794-2 codec produced must survive being wrapped and
// unwrapped, and come back byte-identical. A container that cannot carry a real
// BDB is a container that only works on toy data.
func TestWrapRealMinutiaeRecord(t *testing.T) {
	minutiae := []iso19794b.MinutiaFormat{
		{Type: 2, X: 40, Y: 60, Quality: 88, Orientation: 1.2},
		{Type: 1, X: 90, Y: 120, Quality: 71, Orientation: 3.9},
		{Type: 2, X: 150, Y: 30, Quality: 95, Orientation: 0.4},
	}
	bdb, err := iso19794b.Build(256, 320, 1, 0, 80, minutiae)
	if err != nil {
		t.Fatalf("build 19794-2 record: %v", err)
	}

	rec, err := Wrap(FingerprintHeader(), bdb)
	if err != nil {
		t.Fatal(err)
	}
	h, got, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !h.IsFingerprintMinutiae() {
		t.Fatal("header does not identify a minutiae record")
	}
	if len(got) != len(bdb) {
		t.Fatalf("BDB is %d bytes, original %d", len(got), len(bdb))
	}
	for i := range bdb {
		if got[i] != bdb[i] {
			t.Fatalf("BDB byte %d differs: 0x%02x vs 0x%02x", i, got[i], bdb[i])
		}
	}

	// And the unwrapped block must still parse as what it claims to be.
	if _, err := iso19794b.Parse(got); err != nil {
		t.Fatalf("the unwrapped BDB is not a valid 19794-2 record: %v", err)
	}
}

func TestOwnerAndTypeAreBigEndian(t *testing.T) {
	// Both are 2-byte fields and the standard requires big-endian. A
	// little-endian owner would read as 0x0101 too on a symmetric value, so
	// this pins a value that is NOT symmetric.
	h := Header{
		SecurityOptions: SecurityPlain,
		PatronHeaderVer: patronHeaderVersion,
		BiometricType:   BiometricTypeFinger,
		FormatOwner:     0x0101,
		FormatType:      0x0701, // deliberately asymmetric
	}
	rec, err := Wrap(h, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	// Layout is 3+3+3+4+4 = 17 bytes, so the format-type value sits at 15:17.
	if rec[15] != 0x07 || rec[16] != 0x01 {
		t.Fatalf("format type encoded as %x, want big-endian 0x0701", rec[15:17])
	}
	got, _, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if got.FormatType != 0x0701 {
		t.Fatalf("round-tripped format type 0x%04x, want 0x0701", got.FormatType)
	}
	if binary.BigEndian.Uint16([]byte{0x07, 0x01}) != got.FormatType {
		t.Fatal("parsed value is not the big-endian interpretation")
	}
}
