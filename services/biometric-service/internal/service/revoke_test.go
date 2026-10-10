package service

import (
	"context"
	"testing"

	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
)

func findCandidate(t *testing.T, g *gallery, probe *mcc.Template, pts []minutiae.Minutia, want string) bool {
	t.Helper()
	hits := g.search(context.Background(), probe, pts,
		mcc.NewMatcher(0.35, 60.0, quietLogger()), 20, quietLogger())
	for _, c := range hits {
		if c.EmployeeID == want {
			return true
		}
	}
	return false
}

// TestRevokedEmployeeStopsMatchingWithWarmGallery is the security assertion for
// offboarding, and it is deliberately written against a WARM gallery.
//
// The obvious version of this test - revoke, then search - proves very little,
// because the gallery is a 30-second cached snapshot and a test that searches
// once before and once after may well read through the same populated cache and
// see the stale entry either way. The failure this guards is exactly that: a
// control that updates the database but not the cache leaves the revoked
// template matchable until the TTL expires.
//
// That would leave a terminated employee able to open a door for up to 30
// seconds after being offboarded, which is the window someone already inside
// the building would actually use.
func TestRevokedEmployeeStopsMatchingWithWarmGallery(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)

	addEnrolled(t, repo, v, "EMP-LEAVES", 1, synthPoints(32, 2))
	addEnrolled(t, repo, v, "EMP-STAYS", 1, synthPoints(32, 9))

	svc := NewBiometricService(repo, v, quietLogger())
	galleryOf := svc.(*biometricService).gallery

	pts := synthPoints(32, 2)
	probe := mcc.BuildTemplate("probe", pts)

	// Warm the cache, then prove the leaver is currently matchable.
	if _, _, err := galleryOf.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if !findCandidate(t, galleryOf, probe, pts, "EMP-LEAVES") {
		t.Fatal("precondition: EMP-LEAVES should match its own probe before revocation")
	}

	// Confirm the cache really is warm, so a later pass cannot be explained by
	// a rebuild happening to exclude the revoked row.
	if galleryOf.populated == false {
		t.Fatal("precondition: gallery should be populated before revoking")
	}
	warmReads := repo.reads.Load()

	if _, err := svc.Revoke(ctx, "EMP-LEAVES", 1, "OFFBOARDED"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Revocation must invalidate rather than wait out the TTL.
	if galleryOf.populated {
		t.Fatal("gallery was not invalidated by Revoke; the revoked template stays matchable for the whole TTL")
	}

	if _, _, err := galleryOf.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if repo.reads.Load() <= warmReads {
		t.Fatal("gallery did not rebuild after revocation")
	}

	for _, e := range galleryOf.entries {
		if e.employeeID == "EMP-LEAVES" {
			t.Fatal("revoked employee is still present in the rebuilt gallery")
		}
	}
	if findCandidate(t, galleryOf, probe, pts, "EMP-LEAVES") {
		t.Fatal("a revoked employee still matched a probe")
	}
	if len(galleryOf.entries) != 1 {
		t.Fatalf("gallery holds %d entries, want 1 (only EMP-STAYS)", len(galleryOf.entries))
	}
}

// TestRevokeIsIdempotent covers the retry semantics an offboarding job depends
// on. Running it twice must succeed, and the second run must report that
// nothing was revoked rather than failing.
func TestRevokeIsIdempotent(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "EMP-1", 1, synthPoints(32, 7))
	svc := NewBiometricService(repo, v, quietLogger())

	first, err := svc.Revoke(ctx, "EMP-1", 1, "OFFBOARDED")
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if !first {
		t.Fatal("first revoke reported nothing to revoke")
	}

	second, err := svc.Revoke(ctx, "EMP-1", 1, "OFFBOARDED")
	if err != nil {
		t.Fatalf("second revoke returned an error; an offboarding retry must not fail: %v", err)
	}
	if second {
		t.Fatal("second revoke reported true; it should report that nothing was live")
	}

	// Revoking an employee who was never enrolled is also not an error.
	third, err := svc.Revoke(ctx, "EMP-NEVER", 1, "OFFBOARDED")
	if err != nil {
		t.Fatalf("revoking an unknown employee returned an error: %v", err)
	}
	if third {
		t.Fatal("revoking an unknown employee reported true")
	}
}

func TestRevokeRequiresEmployeeID(t *testing.T) {
	svc := NewBiometricService(&countingRepo{}, testVault(t), quietLogger())
	if _, err := svc.Revoke(context.Background(), "", 1, "OFFBOARDED"); err == nil {
		t.Fatal("revoking with an empty employee id should be rejected")
	}
}

// TestRevokeExcludesFromOneToOneVerification confirms the 1:1 path stops
// serving a revoked template, not just the 1:N gallery.
func TestRevokeExcludesFromOneToOneVerification(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	pts := synthPoints(32, 5)
	addEnrolled(t, repo, v, "EMP-1", 1, pts)
	svc := NewBiometricService(repo, v, quietLogger())

	if _, _, err := svc.GetTemplate(ctx, "EMP-1", 1); err != nil {
		t.Fatalf("precondition: GetTemplate should succeed before revocation: %v", err)
	}

	if _, err := svc.Revoke(ctx, "EMP-1", 1, "OFFBOARDED"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.GetTemplate(ctx, "EMP-1", 1); err == nil {
		t.Fatal("GetTemplate still returns a revoked template")
	}
}

// TestReEnrollAfterRevokeRestoresAccess confirms revocation is not a permanent
// bar: an employee who comes back is re-enrolled normally and matches again.
func TestReEnrollAfterRevokeRestoresAccess(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "EMP-RETURN", 1, synthPoints(32, 3))
	svc := NewBiometricService(repo, v, quietLogger())
	galleryOf := svc.(*biometricService).gallery

	pts := synthPoints(32, 3)
	probe := mcc.BuildTemplate("probe", pts)
	if _, _, err := galleryOf.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if !findCandidate(t, galleryOf, probe, pts, "EMP-RETURN") {
		t.Fatal("precondition: should match before revoking")
	}

	if _, err := svc.Revoke(ctx, "EMP-RETURN", 1, "OFFBOARDED"); err != nil {
		t.Fatal(err)
	}
	if findCandidate(t, galleryOf, probe, pts, "EMP-RETURN") {
		t.Fatal("should not match after revocation")
	}

	// Re-enrolling the same finger must clear the revoked flag, otherwise an
	// employee who returns is permanently locked out.
	addEnrolled(t, repo, v, "EMP-RETURN", 1, synthPoints(32, 3))
	if _, _, err := svc.GetTemplate(ctx, "EMP-RETURN", 1); err != nil {
		t.Fatalf("re-enrollment did not restore access: %v", err)
	}
}

// TestRevokedTemplateIsArchivedForAudit confirms revocation keeps provenance:
// the encrypted payload is retained in the audit trail, because "who was
// enrolled here and when did that stop being true" has to stay answerable
// after someone leaves.
func TestRevokedTemplateIsArchivedForAudit(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "EMP-AUDIT", 1, synthPoints(20, 4))
	svc := NewBiometricService(repo, v, quietLogger())

	before, _, err := svc.GetTemplate(ctx, "EMP-AUDIT", 1)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Revoke(ctx, "EMP-AUDIT", 1, "OFFBOARDED"); err != nil {
		t.Fatal(err)
	}

	hist, err := repo.revocations("EMP-AUDIT")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("revocation history has %d entries, want 1", len(hist))
	}
	if hist[0].Reason != "OFFBOARDED" {
		t.Fatalf("archived reason = %q, want OFFBOARDED", hist[0].Reason)
	}
	if hist[0].TemplateID != before.TemplateID {
		t.Fatalf("archived template id = %q, want %q", hist[0].TemplateID, before.TemplateID)
	}
	if string(hist[0].PriorPayload) != string(before.EncryptedPayload) {
		t.Fatal("archived payload does not match the template that was revoked")
	}
}
