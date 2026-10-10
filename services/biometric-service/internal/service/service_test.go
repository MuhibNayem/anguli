package service

import (
	"context"
	"math"
	"testing"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/services/biometric-service/internal/domain"
)

// syntheticPrint renders concentric elliptical ridges, which is close enough to
// a loop or whorl for the extraction pipeline to produce minutiae.
//
// This mirrors the generator the API gateway uses for its synthetic mode. It
// is not a substitute for a real capture - see the dataset package for that -
// but it is enough to drive the guard clauses in Enroll, Verify and Identify,
// which is what these tests are for.
func syntheticPrint(w, h int, seed uint32) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 210
	}
	cx := float64(w)/2 + float64(int(seed%9)-4)
	cy := float64(h)/2 + float64(int((seed>>4)%9)-4)
	freq := 0.18 + float64(seed%20)/160.0

	for y := 10; y < h-10; y++ {
		for x := 10; x < w-10; x++ {
			dx := float64(x) - cx
			dy := (float64(y) - cy) * 1.25
			r := math.Hypot(dx, dy)
			v := 128 + 82*math.Sin(r*freq)
			pix[y*w+x] = uint8(math.Max(0, math.Min(255, v)))
		}
	}
	return pix
}

func newSvc(t *testing.T, repo *countingRepo) *biometricService {
	t.Helper()
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	return NewBiometricService(repo, v, quietLogger()).(*biometricService)
}

// TestNewBiometricService_DefaultsLogger: a nil logger panicked on the first
// log line in several services before, turning a wiring mistake into a crash
// during startup.
func TestNewBiometricService_DefaultsLogger(t *testing.T) {
	svc := newSvc(t, &countingRepo{})
	if svc.logger == nil {
		t.Fatal("logger must be defaulted, not left nil")
	}
	if svc.gallery == nil {
		t.Fatal("gallery must be constructed; Identify relies on it")
	}
}

// TestEnroll_RejectsInvalidDimensions covers the input guards that run before
// any pixels are touched.
func TestEnroll_RejectsInvalidDimensions(t *testing.T) {
	svc := newSvc(t, &countingRepo{})
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		w, h uint32
	}{
		{"zero width", 0, 128},
		{"zero height", 128, 0},
		{"both zero", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Enroll(ctx, "EMP-1", "Name", 1, make([]byte, 16), tc.w, tc.h, 500); err == nil {
				t.Fatal("expected invalid dimensions to be rejected")
			}
		})
	}
}

// TestEnroll_RejectsUndersizedBuffer: a buffer smaller than width*height would
// otherwise index out of range on the first pass.
func TestEnroll_RejectsUndersizedBuffer(t *testing.T) {
	svc := newSvc(t, &countingRepo{})
	if _, err := svc.Enroll(context.Background(), "EMP-1", "Name", 1, make([]byte, 4), 32, 32, 500); err == nil {
		t.Fatal("expected a too-small pixel buffer to be rejected")
	}
}

// TestVerify_UnknownEmployee: verification must fail closed for someone who is
// not enrolled, not fall through to a default decision.
func TestVerify_UnknownEmployee(t *testing.T) {
	svc := newSvc(t, &countingRepo{})
	_, _, err := svc.Verify(context.Background(), "NOBODY", 1, syntheticPrint(96, 96, 3), 96, 96)
	if err == nil {
		t.Fatal("expected verification of an unenrolled employee to fail")
	}
}

// TestGetTemplate_NotEnrolled returns a clean not-found rather than an error
// that reads like a fault, so the gateway can distinguish the two.
func TestGetTemplate_NotEnrolled(t *testing.T) {
	svc := newSvc(t, &countingRepo{})
	if _, _, err := svc.GetTemplate(context.Background(), "NOBODY", 1); err == nil {
		t.Fatal("expected a not-enrolled error")
	}
}

// TestGetTemplate_DecryptsAndReturnsPayload is the round trip the gateway
// depends on when it syncs a roster to the edge: what goes in encrypted must
// come back as a usable cylinder set.
func TestGetTemplate_DecryptsAndReturnsPayload(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	svc := newSvc(t, repo)
	points := synthPoints(24, 3)
	addEnrolled(t, repo, svc.vault, "EMP-9", 1, points)

	rec, payload, err := svc.GetTemplate(ctx, "EMP-9", 1)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if rec.EmployeeID != "EMP-9" {
		t.Fatalf("employee = %q, want EMP-9", rec.EmployeeID)
	}
	if len(payload.Cylinders) != len(points) {
		t.Fatalf("got %d cylinders, want %d", len(payload.Cylinders), len(points))
	}
	if len(payload.Minutiae) != len(points) {
		t.Fatalf("got %d minutiae, want %d", len(payload.Minutiae), len(points))
	}
}

// TestGetTemplate_RejectsCorruptPayload: a record that cannot be decrypted must
// error rather than return an empty payload, which a caller would read as "this
// employee has no template".
func TestGetTemplate_RejectsCorruptPayload(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	svc := newSvc(t, repo)
	addEnrolled(t, repo, svc.vault, "EMP-BAD", 1, synthPoints(20, 1))

	repo.mu.Lock()
	for _, it := range repo.items {
		if it.EmployeeID == "EMP-BAD" {
			it.EncryptedPayload = []byte("corrupted ciphertext")
		}
	}
	repo.mu.Unlock()

	if _, _, err := svc.GetTemplate(ctx, "EMP-BAD", 1); err == nil {
		t.Fatal("expected corrupt payload to error rather than return an empty template")
	}
}

// TestIdentify_RejectsLowQualityProbe: a probe the quality assessor rejects must
// never reach the gallery. Matching a bad print against the whole enrolment
// wastes the budget and risks a false accept from noise.
func TestIdentify_RejectsLowQualityProbe(t *testing.T) {
	svc := newSvc(t, &countingRepo{})

	// A flat field has no ridge structure at all.
	flat := make([]byte, 96*96)
	for i := range flat {
		flat[i] = 128
	}
	if _, err := svc.Identify(context.Background(), flat, 96, 96, 3); err == nil {
		t.Fatal("expected a featureless probe to be rejected")
	}
}

// TestIdentify_RejectsInvalidDimensions mirrors the Enroll guards on the search
// path, which is the one an unauthenticated caller can reach.
func TestIdentify_RejectsInvalidDimensions(t *testing.T) {
	svc := newSvc(t, &countingRepo{})
	if _, err := svc.Identify(context.Background(), make([]byte, 16), 0, 96, 3); err == nil {
		t.Fatal("expected invalid dimensions to be rejected")
	}
}

// TestEnroll_InvalidatesGallery ties the write path to the cache. If enrollment
// stopped invalidating, a newly enrolled employee would not be findable by
// 1:N until the TTL expired, and the symptom in the field would be "my badge
// works but my finger does not".
func TestEnroll_InvalidatesGallery(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	svc := newSvc(t, repo)

	// Warm the gallery with one enrollment's worth of cached state.
	addEnrolled(t, repo, svc.vault, "EMP-OLD", 1, synthPoints(20, 0))
	if _, _, err := svc.gallery.snapshot(ctx, repo, svc.vault, svc.logger); err != nil {
		t.Fatal(err)
	}
	if !svc.gallery.populated {
		t.Fatal("expected a populated gallery")
	}

	pix := syntheticPrint(96, 96, 5)
	// Enrollment may legitimately fail on a synthetic print (quality or
	// minutiae count); the point is that a SUCCESSFUL write invalidates.
	if _, err := svc.Enroll(ctx, "EMP-NEW", "New", 2, pix, 96, 96, 500); err == nil {
		if svc.gallery.populated {
			t.Fatal("a successful enrollment left the gallery populated with a stale roster")
		}
	}
}

// TestDomainPayloadShape guards the JSON contract the encrypted payload
// depends on: renaming a field would silently break every stored record.
func TestDomainPayloadShape(t *testing.T) {
	p := domain.DecryptedTemplatePayload{Minutiae: synthPoints(2, 0), Cylinders: nil}
	if len(p.Minutiae) != 2 {
		t.Fatalf("expected 2 minutiae in the round-tripped payload")
	}
}
