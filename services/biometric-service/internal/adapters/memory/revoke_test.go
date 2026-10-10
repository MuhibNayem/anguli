package memory

import (
	"context"
	"testing"

	"finger-scanner/services/biometric-service/internal/domain"
)

func saveT(t *testing.T, r *inMemoryRepository, id string, pos int32) *domain.EnrolledTemplate {
	t.Helper()
	tmpl := &domain.EnrolledTemplate{
		TemplateID:       "tmpl-" + id,
		EmployeeID:       id,
		FullName:         "Test " + id,
		Position:         pos,
		NFIQScore:        80,
		MinutiaeCount:    20,
		EncryptedPayload: []byte("ciphertext-" + id),
		EnrolledAtUnix:   1700000000,
	}
	if err := r.Save(context.Background(), tmpl); err != nil {
		t.Fatal(err)
	}
	return tmpl
}

// TestRevokeFlagsAndArchives mirrors the sqlstore proof so the two adapters
// cannot drift apart. If the in-memory adapter ever behaves differently from
// the durable one, a deployment that swaps backends silently changes whether an
// offboarded employee can still open a door.
func TestRevokeFlagsAndArchives(t *testing.T) {
	ctx := context.Background()
	impl := NewInMemoryRepository().(*inMemoryRepository)
	r := impl
	tmpl := saveT(t, impl, "EMP-1", 1)

	revoked, err := r.Revoke(ctx, "EMP-1", 1, "OFFBOARDED", 1700009999)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !revoked {
		t.Fatal("Revoke reported nothing to revoke for a live template")
	}

	if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-1", 1); err == nil {
		t.Fatal("GetByEmployeeAndPosition still returns a revoked template")
	}

	all, err := r.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.EmployeeID == "EMP-1" {
			t.Fatal("ListAll still returns a revoked template")
		}
	}

	if len(impl.auditHistory) != 1 {
		t.Fatalf("audit history has %d entries, want 1", len(impl.auditHistory))
	}
	rec := impl.auditHistory[0]
	if rec.Reason != "OFFBOARDED" {
		t.Fatalf("archived reason = %q, want OFFBOARDED", rec.Reason)
	}
	if rec.TemplateID != tmpl.TemplateID {
		t.Fatalf("archived template id = %q, want %q", rec.TemplateID, tmpl.TemplateID)
	}
	if string(rec.PriorPayload) != string(tmpl.EncryptedPayload) {
		t.Fatal("archived payload does not match what was stored")
	}
	if rec.RevokedAtUnix != 1700009999 {
		t.Fatalf("archived timestamp = %d, want 1700009999", rec.RevokedAtUnix)
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRepository().(*inMemoryRepository)
	saveT(t, r, "EMP-2", 1)

	if _, err := r.Revoke(ctx, "EMP-2", 1, "OFFBOARDED", 1); err != nil {
		t.Fatal(err)
	}
	second, err := r.Revoke(ctx, "EMP-2", 1, "OFFBOARDED", 2)
	if err != nil {
		t.Fatalf("second revoke returned an error: %v", err)
	}
	if second {
		t.Fatal("second revoke reported true")
	}

	// A retry must not append a second audit record; the first revocation is
	// the one that happened.
	if got := len(r.auditHistory); got != 1 {
		t.Fatalf("audit history has %d entries after a retry, want 1", got)
	}
}

func TestRevokeUnknownEmployee(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRepository()
	revoked, err := r.Revoke(ctx, "EMP-NOBODY", 1, "OFFBOARDED", 1)
	if err != nil {
		t.Fatalf("revoking an unknown employee returned an error: %v", err)
	}
	if revoked {
		t.Fatal("revoking an unknown employee reported true")
	}
}

func TestRevokeRequiresEmployeeID(t *testing.T) {
	r := NewInMemoryRepository()
	if _, err := r.Revoke(context.Background(), "", 1, "OFFBOARDED", 1); err == nil {
		t.Fatal("revoking with an empty employee id should be rejected")
	}
}

func TestRevokeDefaultsEmptyReason(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRepository().(*inMemoryRepository)
	saveT(t, r, "EMP-3", 1)

	if _, err := r.Revoke(ctx, "EMP-3", 1, "", 1); err != nil {
		t.Fatal(err)
	}
	if len(r.auditHistory) != 1 || r.auditHistory[0].Reason != "UNSPECIFIED" {
		t.Fatalf("blank reason should be recorded as UNSPECIFIED, got %+v", r.auditHistory)
	}
}

// TestRevokeOnlyAffectsTheNamedFinger guards against removing more than asked.
func TestRevokeOnlyAffectsTheNamedFinger(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRepository().(*inMemoryRepository)
	for pos := int32(1); pos <= 3; pos++ {
		saveT(t, r, "EMP-4", pos)
	}

	if _, err := r.Revoke(ctx, "EMP-4", 2, "OFFBOARDED", 1); err != nil {
		t.Fatal(err)
	}

	if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-4", 2); err == nil {
		t.Fatal("position 2 should be revoked")
	}
	for _, pos := range []int32{1, 3} {
		if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-4", pos); err != nil {
			t.Fatalf("position %d should survive, got %v", pos, err)
		}
	}
}

// TestReEnrollAfterRevokeRestoresAccess confirms an employee who returns is not
// permanently locked out.
func TestReEnrollAfterRevokeRestoresAccess(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRepository().(*inMemoryRepository)
	saveT(t, r, "EMP-5", 1)

	if _, err := r.Revoke(ctx, "EMP-5", 1, "OFFBOARDED", 1); err != nil {
		t.Fatal(err)
	}

	again := saveT(t, r, "EMP-5", 1)
	if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-5", 1); err != nil {
		t.Fatalf("re-enrollment did not restore access: %v", err)
	}
	all, err := r.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Revoked {
		t.Fatalf("ListAll returned %d entries (revoked=%v), want 1 live entry", len(all), all[0].Revoked)
	}
	_ = again
}
