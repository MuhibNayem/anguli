package sqlstore

import (
	"context"
	"errors"
	"testing"

	"finger-scanner/pkg/store"
)

// TestRevokeFlagsAndArchives is the persistence-level offboarding proof.
//
// Two things have to be true at once and neither is implied by the other: the
// template must stop being readable through every query path, and its payload
// must survive in the audit trail. A delete would satisfy the first and break
// the second; an archive that leaves the row live would satisfy the second and
// silently fail the first.
func TestRevokeFlagsAndArchives(t *testing.T) {
	ctx := context.Background()
	st := openTemp(t, t.TempDir())
	defer func() { _ = st.Close() }()
	r := newRepo(t, st)

	tmpl := sample("EMP-1", 1)
	if err := r.Save(ctx, tmpl); err != nil {
		t.Fatal(err)
	}

	revoked, err := r.Revoke(ctx, "EMP-1", 1, "OFFBOARDED", 1700009999)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !revoked {
		t.Fatal("Revoke reported nothing to revoke for a live template")
	}

	// Must vanish from the 1:1 read path.
	if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-1", 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByEmployeeAndPosition after revoke = %v; want ErrNotFound", err)
	}

	// Must vanish from the 1:N gallery read path.
	all, err := r.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.EmployeeID == "EMP-1" {
			t.Fatal("ListAll still returns a revoked template; it would stay matchable in 1:N search")
		}
	}

	// But the payload must survive for audit.
	hist, err := r.RevocationHistory(ctx, "EMP-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("RevocationHistory returned %d records, want 1", len(hist))
	}
	if hist[0].Reason != "OFFBOARDED" {
		t.Fatalf("archived reason = %q, want OFFBOARDED", hist[0].Reason)
	}
	if hist[0].RevokedAtUnix != 1700009999 {
		t.Fatalf("archived timestamp = %d, want 1700009999", hist[0].RevokedAtUnix)
	}
	if string(hist[0].PriorPayload) != string(tmpl.EncryptedPayload) {
		t.Fatal("archived payload does not match what was stored")
	}
}

// TestRevokeIsIdempotentAcrossRestart covers the retry contract against real
// storage: an offboarding job that runs twice, or that is re-run after a
// restart, must not fail and must not write a duplicate audit record.
func TestRevokeIsIdempotentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openTemp(t, dir)
	r := newRepo(t, st)

	if err := r.Save(ctx, sample("EMP-2", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Revoke(ctx, "EMP-2", 1, "OFFBOARDED", 1700000000); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the same file and retry.
	st2 := openTemp(t, dir)
	defer func() { _ = st2.Close() }()
	r2 := newRepo(t, st2)

	revoked, err := r2.Revoke(ctx, "EMP-2", 1, "OFFBOARDED", 1700000001)
	if err != nil {
		t.Fatalf("retry after restart returned an error: %v", err)
	}
	if revoked {
		t.Fatal("retry reported true; nothing was live")
	}

	hist, err := r2.RevocationHistory(ctx, "EMP-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("RevocationHistory returned %d records after a retry; want 1", len(hist))
	}
}

func TestRevokeUnknownEmployee(t *testing.T) {
	ctx := context.Background()
	st := openTemp(t, t.TempDir())
	defer func() { _ = st.Close() }()
	r := newRepo(t, st)

	revoked, err := r.Revoke(ctx, "EMP-NOBODY", 1, "OFFBOARDED", 1700000000)
	if err != nil {
		t.Fatalf("revoking an unknown employee returned an error: %v", err)
	}
	if revoked {
		t.Fatal("revoking an unknown employee reported true")
	}
}

func TestRevokeRequiresEmployeeID(t *testing.T) {
	ctx := context.Background()
	st := openTemp(t, t.TempDir())
	defer func() { _ = st.Close() }()
	r := newRepo(t, st)

	if _, err := r.Revoke(ctx, "", 1, "OFFBOARDED", 1700000000); err == nil {
		t.Fatal("revoking with an empty employee id should be rejected")
	}
}

// TestRevokeOnlyAffectsTheNamedFinger guards against an offboarding call that
// removes more than asked: revoking one position must leave the employee's
// other enrolled fingers intact, or a payroll integration that revokes by
// position could lock someone out of fingers they are still entitled to use.
func TestRevokeOnlyAffectsTheNamedFinger(t *testing.T) {
	ctx := context.Background()
	st := openTemp(t, t.TempDir())
	defer func() { _ = st.Close() }()
	r := newRepo(t, st)

	for pos := int32(1); pos <= 3; pos++ {
		if err := r.Save(ctx, sample("EMP-3", pos)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := r.Revoke(ctx, "EMP-3", 2, "OFFBOARDED", 1700000000); err != nil {
		t.Fatal(err)
	}

	if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-3", 2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("position 2 should be revoked, got %v", err)
	}
	for _, pos := range []int32{1, 3} {
		if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-3", pos); err != nil {
			t.Fatalf("position %d should survive revoking position 2, got %v", pos, err)
		}
	}
}

// TestReEnrollAfterRevokeRestoresAccess confirms the revoked flag is cleared by
// a later enrollment, so an employee who returns is not permanently locked out.
func TestReEnrollAfterRevokeRestoresAccess(t *testing.T) {
	ctx := context.Background()
	st := openTemp(t, t.TempDir())
	defer func() { _ = st.Close() }()
	r := newRepo(t, st)

	if err := r.Save(ctx, sample("EMP-4", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Revoke(ctx, "EMP-4", 1, "OFFBOARDED", 1700000000); err != nil {
		t.Fatal(err)
	}

	again := sample("EMP-4", 1)
	again.Revoked = false
	if err := r.Save(ctx, again); err != nil {
		t.Fatal(err)
	}

	if _, err := r.GetByEmployeeAndPosition(ctx, "EMP-4", 1); err != nil {
		t.Fatalf("re-enrollment did not restore access: %v", err)
	}
	all, err := r.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("ListAll returned %d templates after re-enrollment, want 1", len(all))
	}
}
