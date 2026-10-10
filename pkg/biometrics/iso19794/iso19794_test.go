package iso19794

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"
)

// samplePixels builds a deterministic greyscale image.
func samplePixels(w, h int) []byte {
	p := make([]byte, w*h)
	r := rand.New(rand.NewSource(42))
	for i := range p {
		p[i] = byte(r.Intn(256))
	}
	return p
}

// TestRoundTrip_Lossless is the core interop property: an image exported by
// BuildImage must come back from ParseImage byte for byte. If this fails, an
// exported template would not match the one the platform enrolled.
func TestRoundTrip_Lossless(t *testing.T) {
	for _, dims := range [][2]int{{64, 64}, {120, 120}, {200, 200}, {1, 1}} {
		w, h := dims[0], dims[1]
		px := samplePixels(w, h)

		raw, err := BuildImage(px, w, h, 500)
		if err != nil {
			t.Fatalf("BuildImage %dx%d: %v", w, h, err)
		}
		got, err := ParseImage(raw)
		if err != nil {
			t.Fatalf("ParseImage %dx%d: %v", w, h, err)
		}
		if got.Width != w || got.Height != h {
			t.Errorf("dimensions = %dx%d; want %dx%d", got.Width, got.Height, w, h)
		}
		if !bytes.Equal(got.Pixels, px) {
			t.Errorf("pixels corrupted on round trip for %dx%d", w, h)
		}
		if got.Representation != Rep8BitLinear {
			t.Errorf("representation = 0x%02X; want 0x01", byte(got.Representation))
		}
		if got.SubjectCount != 1 {
			t.Errorf("SubjectCount = %d; want 1", got.SubjectCount)
		}
	}
}

// TestBuildImage_HeaderLayout pins the byte offsets against
// ISO/IEC 19794-4:2009 table 4. An off-by-one here produces records that look
// plausible and are rejected by every conforming reader.
func TestBuildImage_HeaderLayout(t *testing.T) {
	const w, h, dpi = 64, 48, 500
	raw, err := BuildImage(samplePixels(w, h), w, h, dpi)
	if err != nil {
		t.Fatal(err)
	}

	hdr, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Format != formatImageRecord {
		t.Errorf("format = 0x%08X; want 0x%08X", hdr.Format, formatImageRecord)
	}
	if hdr.Version != 0x00300000 {
		t.Errorf("version = 0x%08X; want 0x00300000", hdr.Version)
	}
	if int(hdr.RecordLen) != len(raw) {
		t.Errorf("record length = %d; want %d", hdr.RecordLen, len(raw))
	}
	if int(hdr.DataBlockWidth) != w || int(hdr.DataBlockHeight) != h {
		t.Errorf("data block = %dx%d; want %dx%d",
			hdr.DataBlockWidth, hdr.DataBlockHeight, w, h)
	}
	if hdr.ResolutionUnits != 0 {
		t.Errorf("resolution units = %d; want 0 (pixels per inch)", hdr.ResolutionUnits)
	}
	if hdr.ResolutionX != dpi || hdr.ResolutionY != dpi {
		t.Errorf("resolution = %dx%d; want %d", hdr.ResolutionX, hdr.ResolutionY, dpi)
	}
	if hdr.NumImages != 1 {
		t.Errorf("num images = %d; want 1", hdr.NumImages)
	}
	if hdr.SubjectCount != 1 {
		t.Errorf("subject count = %d; want 1", hdr.SubjectCount)
	}

	// Verify raw offsets directly as well, so a parser bug cannot mask a
	// layout bug.
	if got := binary.BigEndian.Uint32(raw[0:4]); got != formatImageRecord {
		t.Errorf("raw bytes [0:4] = 0x%08X", got)
	}
	if raw[16] != 0 {
		t.Errorf("raw byte [16] = %d; want 0 (resolution units)", raw[16])
	}
	if got := binary.BigEndian.Uint16(raw[17:19]); got != dpi {
		t.Errorf("raw bytes [17:19] = %d; want %d", got, dpi)
	}
	if raw[21] != 1 {
		t.Errorf("raw byte [21] = %d; want 1 (num images)", raw[21])
	}
	if raw[22] != 1 {
		t.Errorf("raw byte [22] = %d; want 1 (subject count)", raw[22])
	}
}

func TestParseHeader_TooShort(t *testing.T) {
	for n := 0; n < RecordHeaderLen; n++ {
		if _, err := ParseHeader(make([]byte, n)); !errors.Is(err, ErrTooShort) {
			t.Errorf("ParseHeader(%d bytes) = %v; want ErrTooShort", n, err)
		}
	}
}

// TestParseImage_RejectsForeignFormat: a minutiae or finger record must not be
// silently reinterpreted as an image.
func TestParseImage_RejectsForeignFormat(t *testing.T) {
	raw, err := BuildImage(samplePixels(16, 16), 16, 16, 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []uint32{formatFingerRecord, formatMinutiaeData, 0xDEADBEEF, 0} {
		binary.BigEndian.PutUint32(raw[0:4], bad)
		if _, err := ParseImage(raw); !errors.Is(err, ErrBadMagic) {
			t.Errorf("format 0x%08X = %v; want ErrBadMagic", bad, err)
		}
	}
}

func TestParseImage_RejectsWrongVersion(t *testing.T) {
	raw, _ := BuildImage(samplePixels(16, 16), 16, 16, 500)
	binary.BigEndian.PutUint32(raw[4:8], 0x00200000)
	if _, err := ParseImage(raw); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("error = %v; want ErrBadVersion", err)
	}
}

// TestParseImage_RejectsTruncatedRecord is the important one. Accepting a
// truncated record would let a partial image be enrolled as if it were whole.
func TestParseImage_RejectsTruncatedRecord(t *testing.T) {
	full, _ := BuildImage(samplePixels(64, 64), 64, 64, 500)
	for _, cut := range []int{RecordHeaderLen + 4, len(full) - 1, len(full) / 2} {
		if _, err := ParseImage(full[:cut]); err == nil {
			t.Errorf("ParseImage on a %d-byte truncation = nil error", cut)
		}
	}
}

// TestParseImage_RejectsLengthMismatch: the declared record length must agree
// with the bytes supplied, in both directions.
func TestParseImage_RejectsLengthMismatch(t *testing.T) {
	raw, _ := BuildImage(samplePixels(64, 64), 64, 64, 500)
	binary.BigEndian.PutUint32(raw[8:12], uint32(len(raw)+100))
	if _, err := ParseImage(raw); !errors.Is(err, ErrRecordLengthMismatch) {
		t.Errorf("over-declared length = %v; want ErrRecordLengthMismatch", err)
	}

	raw2, _ := BuildImage(samplePixels(64, 64), 64, 64, 500)
	binary.BigEndian.PutUint32(raw2[8:12], uint32(len(raw2)-1))
	if _, err := ParseImage(raw2); !errors.Is(err, ErrRecordLengthMismatch) {
		t.Errorf("under-declared length = %v; want ErrRecordLengthMismatch", err)
	}
}

func TestParseImage_RejectsDimensionDisagreement(t *testing.T) {
	raw, _ := BuildImage(samplePixels(64, 64), 64, 64, 500)
	body := raw[RecordHeaderLen:]
	binary.BigEndian.PutUint16(body[1:3], 128) // image width now disagrees

	if _, err := ParseImage(raw); !errors.Is(err, ErrInconsistentDimensions) {
		t.Fatalf("error = %v; want ErrInconsistentDimensions", err)
	}
}

func TestParseImage_RejectsUnsupportedResolution(t *testing.T) {
	raw, _ := BuildImage(samplePixels(64, 64), 64, 64, 500)
	binary.BigEndian.PutUint16(raw[17:19], 1200)
	binary.BigEndian.PutUint16(raw[19:21], 1200)

	if _, err := ParseImage(raw); !errors.Is(err, ErrUnsupportedResolution) {
		t.Fatalf("error = %v; want ErrUnsupportedResolution", err)
	}
}

func TestDPIPerPixel_ConvertsFromDpcm(t *testing.T) {
	h := Header{ResolutionUnits: 1, ResolutionX: 200}
	dpi, err := h.DPIPerPixel()
	if err != nil {
		t.Fatal(err)
	}
	if dpi < 507 || dpi > 508 {
		t.Errorf("200 dpcm = %.2f dpi; want ~508", dpi)
	}

	h.ResolutionUnits = 2
	if _, err := h.DPIPerPixel(); !errors.Is(err, ErrUnsupportedResolution) {
		t.Errorf("resolution units 2 = %v; want ErrUnsupportedResolution", err)
	}
}

func TestBuildImage_RejectsBadInput(t *testing.T) {
	px := samplePixels(64, 64)
	cases := map[string]struct {
		px   []byte
		w, h int
		dpi  uint16
	}{
		"zero width":         {px, 0, 64, 500},
		"zero height":        {px, 64, 0, 500},
		"negative width":     {px, -1, 64, 500},
		"too few pixels":     {make([]byte, 100), 64, 64, 500},
		"unsupported dpi":    {px, 64, 64, 1234},
		"dpi below range":    {px, 64, 64, 0},
		"dimension overflow": {px, 70000, 70000, 500},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildImage(c.px, c.w, c.h, c.dpi); err == nil {
				t.Errorf("BuildImage(%s) = nil error", name)
			}
		})
	}
}

func TestParseImage_RejectsMultiImageRecord(t *testing.T) {
	raw, _ := BuildImage(samplePixels(32, 32), 32, 32, 500)
	raw[21] = 2
	if _, err := ParseImage(raw); err == nil {
		t.Fatal("ParseImage accepted a multi-image record; it must not be mapped to one enrollment")
	}
}

func TestParseImage_RejectsMultiSubjectRecord(t *testing.T) {
	raw, _ := BuildImage(samplePixels(32, 32), 32, 32, 500)
	binary.BigEndian.PutUint16(raw[RecordHeaderLen+9:RecordHeaderLen+11], 2)
	if _, err := ParseImage(raw); err == nil {
		t.Fatal("ParseImage accepted a two-subject record")
	}
}

func TestParseImage_RejectsUnsupportedRepresentation(t *testing.T) {
	raw, _ := BuildImage(samplePixels(32, 32), 32, 32, 500)
	raw[RecordHeaderLen] = 0x07 // JPEG2000, which this pipeline does not decode
	if _, err := ParseImage(raw); err == nil {
		t.Fatal("ParseImage accepted an unsupported image representation")
	}
}

func TestIsFingerImageRecord(t *testing.T) {
	raw, _ := BuildImage(samplePixels(16, 16), 16, 16, 500)
	if !IsFingerImageRecord(raw) {
		t.Error("IsFingerImageRecord = false for a valid image record")
	}
	if IsFingerImageRecord(raw[:3]) {
		t.Error("IsFingerImageRecord = true for a 3-byte buffer")
	}
	binary.BigEndian.PutUint32(raw[0:4], formatFingerRecord)
	if IsFingerImageRecord(raw) {
		t.Error("IsFingerImageRecord = true for a finger (non-image) record")
	}
}

// TestParseImage_NeverPanicsOnArbitraryBytes walks hostile inputs. This parser
// will be handed files from an external database, so malformed bytes must
// produce errors rather than crash the enrollment service.
func TestParseImage_NeverPanicsOnArbitraryBytes(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 500; i++ {
		n := r.Intn(200)
		b := make([]byte, n)
		r.Read(b)
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("ParseImage panicked on %d random bytes: %v", n, rec)
				}
			}()
			_, _ = ParseImage(b)
			_, _ = ParseHeader(b)
			_ = IsFingerImageRecord(b)
		}()
	}
}

// TestParseImage_MutationIsDetected: flipping a byte in the pixel data must
// either change the decoded image or be rejected. Silence would mean a corrupt
// file passing validation.
func TestParseImage_MutationIsDetected(t *testing.T) {
	px := samplePixels(64, 64)
	raw, _ := BuildImage(px, 64, 64, 500)
	original, err := ParseImage(raw)
	if err != nil {
		t.Fatal(err)
	}

	mutated := append([]byte(nil), raw...)
	mutated[len(mutated)-1] ^= 0xFF
	got, err := ParseImage(mutated)
	if err != nil {
		return // rejecting is also acceptable
	}
	if bytes.Equal(got.Pixels, original.Pixels) {
		t.Error("a mutated final byte produced an identical image; the corruption went undetected")
	}
}
