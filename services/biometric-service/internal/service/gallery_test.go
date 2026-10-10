package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/services/biometric-service/internal/domain"
)

// countingRepo records how many times the enrolment table was read, which is
// the whole point of the gallery: the expensive scan must happen once, not
// once per walk-up.
type countingRepo struct {
	mu      sync.Mutex
	items   []*domain.EnrolledTemplate
	revoked []*domain.RevocationRecord
	reads   atomic.Int64
}

func (r *countingRepo) Save(ctx context.Context, t *domain.EnrolledTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.items {
		if existing.EmployeeID == t.EmployeeID && existing.Position == t.Position {
			r.items[i] = t
			return nil
		}
	}
	r.items = append(r.items, t)
	return nil
}

func (r *countingRepo) GetByEmployeeAndPosition(_ context.Context, empID string, pos int32) (*domain.EnrolledTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, it := range r.items {
		if it.EmployeeID == empID && it.Position == pos && !it.Revoked {
			return it, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

// ListAll excludes revoked templates, matching both real adapters. If this stub
// ignored the flag, a test asserting that a revoked employee stops matching
// would pass for the wrong reason here and fail against real storage.
func (r *countingRepo) ListAll(context.Context) ([]*domain.EnrolledTemplate, error) {
	r.reads.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.EnrolledTemplate, 0, len(r.items))
	for _, it := range r.items {
		if !it.Revoked {
			out = append(out, it)
		}
	}
	return out, nil
}

func (r *countingRepo) Revoke(
	_ context.Context, empID string, pos int32, reason string, atUnix int64,
) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, it := range r.items {
		if it.EmployeeID == empID && it.Position == pos && !it.Revoked {
			cp := *it
			cp.Revoked = true
			r.items[i] = &cp
			r.revoked = append(r.revoked, &domain.RevocationRecord{
				TemplateID:    it.TemplateID,
				EmployeeID:    it.EmployeeID,
				Position:      it.Position,
				RevokedAtUnix: atUnix,
				Reason:        reason,
				PriorPayload:  it.EncryptedPayload,
			})
			return true, nil
		}
	}
	return false, nil
}

// revocations mirrors RevocationHistory for assertions about audit provenance.
func (r *countingRepo) revocations(empID string) ([]*domain.RevocationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.RevocationRecord, 0, len(r.revoked))
	for _, rec := range r.revoked {
		if rec.EmployeeID == empID {
			out = append(out, rec)
		}
	}
	return out, nil
}

func testVault(t *testing.T) *crypto.Vault {
	t.Helper()
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	return v
}

// synthPoints builds n deterministic pseudo-random minutiae.
//
// Deterministic rather than random because a flaky fingerprint matcher makes
// every test in this package a coin flip.
func synthPoints(n, seed int) []minutiae.Minutia {
	pts := make([]minutiae.Minutia, n)
	for i := 0; i < n; i++ {
		pts[i] = minutiae.Minutia{
			X:       uint16(10 + ((i*37 + seed*11) % 180)),
			Y:       uint16(10 + ((i*53 + seed*7) % 180)),
			Angle:   float64((i*29+seed)%360) * 3.14159265358979 / 180.0,
			Type:    minutiae.TypeBifurcation,
			Quality: 90,
		}
	}
	return pts
}

// addEnrolled encrypts points into repo under empID.
func addEnrolled(t *testing.T, repo *countingRepo, v *crypto.Vault, empID string, pos int32, points []minutiae.Minutia) {
	t.Helper()
	payload, err := json.Marshal(domain.DecryptedTemplatePayload{
		Minutiae:  points,
		Cylinders: mcc.BuildTemplate(empID, points).Cylinders,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := v.EncryptTemplate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(context.Background(), &domain.EnrolledTemplate{
		TemplateID:       empID + "-" + fmt.Sprint(pos),
		EmployeeID:       empID,
		Position:         pos,
		EncryptedPayload: ct,
	}); err != nil {
		t.Fatal(err)
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestGallery_ReadsEnrolmentOnceAcrossSearches is the performance regression
// test. Before the gallery, every Identify re-read the whole enrolment table
// and re-decrypted every record; at campus scale that is the difference
// between a turnstile opening in milliseconds and one that does not open at
// all.
func TestGallery_ReadsEnrolmentOnceAcrossSearches(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	for i := 0; i < 20; i++ {
		addEnrolled(t, repo, v, fmt.Sprintf("EMP-%03d", i), 1, synthPoints(24, i))
	}

	g := &gallery{}
	probe := mcc.BuildTemplate("probe", synthPoints(24, 0))

	for i := 0; i < 10; i++ {
		if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		g.search(ctx, probe, synthPoints(24, 0), mcc.NewMatcher(0.35, 60.0, quietLogger()), 5, quietLogger())
	}

	if reads := repo.reads.Load(); reads != 1 {
		t.Fatalf("enrolment table read %d times across 10 searches; the gallery should read it once", reads)
	}
}

// TestGallery_InvalidateForcesRebuildAfterEnroll guards the correctness
// consequence of caching: a newly enrolled finger must become searchable at
// once. A cache that is never invalidated would quietly make new enrolments
// unfindable, and the symptom - "my badge works but my finger does not" - is
// very hard to diagnose in the field.
func TestGallery_InvalidateForcesRebuildAfterEnroll(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "EMP-000", 1, synthPoints(20, 0))

	g := &gallery{}
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if got := len(g.entries); got != 1 {
		t.Fatalf("expected 1 entry, got %d", got)
	}

	addEnrolled(t, repo, v, "EMP-001", 1, synthPoints(20, 1))
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if got := len(g.entries); got != 1 {
		t.Fatalf("cache served a stale roster of %d entries after an enrollment; expected the pre-enroll snapshot", got)
	}

	g.invalidate()
	entries, _, err := g.snapshot(ctx, repo, v, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("after invalidate the gallery has %d entries; the new enrollment is not searchable", len(entries))
	}
}

// TestGallery_TTLForcesRebuild covers the multi-replica case a local
// invalidate cannot see: another process enrolled someone, so this process
// only learns by expiring its cache.
func TestGallery_TTLForcesRebuild(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "EMP-000", 1, synthPoints(20, 0))

	g := &gallery{}
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}

	addEnrolled(t, repo, v, "EMP-001", 1, synthPoints(20, 1))

	// Backdate the load rather than sleeping 30s.
	g.mu.Lock()
	g.loadedAt = time.Now().Add(-2 * galleryTTL)
	g.mu.Unlock()

	entries, reloaded, err := g.snapshot(ctx, repo, v, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("expired gallery was not reloaded")
	}
	if len(entries) != 2 {
		t.Fatalf("expired gallery rebuilt to %d entries; an enrollment from another replica stays invisible", len(entries))
	}
}

// TestGallery_PrefilterKeepsPlausibleCandidates pins the filter's two edges:
// an implausible minutiae count is dropped, and the bound is wide enough that
// a true match with a modestly different count survives. A filter tuned too
// tight turns a performance win into a false negative for exactly the
// employees whose finger gave a marginal read.
func TestGallery_PrefilterKeepsPlausibleCandidates(t *testing.T) {
	probe := mcc.BuildTemplate("probe", synthPoints(40, 0))
	probeN := len(probe.Cylinders)

	g := &gallery{entries: []galleryEntry{
		{employeeID: "SAME", template: mcc.BuildTemplate("same", synthPoints(40, 0)), minutiae: probeN},
		{employeeID: "NEAR", template: mcc.BuildTemplate("near", synthPoints(38, 1)), minutiae: probeN - 2},
		{employeeID: "FAR", template: mcc.BuildTemplate("far", synthPoints(4, 2)), minutiae: 4},
	}, populated: true, loadedAt: time.Now()}

	// Verify what the filter alone selects, without depending on whether the
	// matcher would happen to accept each candidate.
	tolerance := int(float64(probeN)*galleryMinutiaeTolerance) + 1
	kept := 0
	for _, e := range g.entries {
		if diff := e.minutiae - probeN; diff <= tolerance && diff >= -tolerance {
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("prefilter kept %d of 3 candidates; want the same-count and near-count ones", kept)
	}
	if tolerance < 2 {
		t.Fatalf("tolerance %d is too tight to survive a 2-minutiae extraction difference", tolerance)
	}
}

// TestGallery_SkipsUnreadableRecordsWithoutFailing: one corrupt enrolment must
// not blind the whole gallery, or a single bad record disables 1:N for the
// entire facility.
func TestGallery_SkipsUnreadableRecordsWithoutFailing(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "GOOD", 1, synthPoints(20, 0))
	addEnrolled(t, repo, v, "CORRUPT", 1, synthPoints(20, 1))
	// Overwrite with bytes that are not valid ciphertext.
	repo.mu.Lock()
	for _, it := range repo.items {
		if it.EmployeeID == "CORRUPT" {
			it.EncryptedPayload = []byte("not a real ciphertext at all")
		}
	}
	repo.mu.Unlock()

	g := &gallery{}
	entries, _, err := g.snapshot(ctx, repo, v, quietLogger())
	if err != nil {
		t.Fatalf("a single unreadable record must not fail the whole gallery: %v", err)
	}
	if len(entries) != 1 || entries[0].employeeID != "GOOD" {
		t.Fatalf("expected only GOOD in the gallery, got %+v", entries)
	}
}

// TestGallery_SearchIsDeterministicUnderConcurrency: the parallel search must
// return the same ranking every run. A matcher that is pure per call but
// assembled non-deterministically would produce an identification that
// changes between identical scans, which is not something an access decision
// can be allowed to do.
func TestGallery_SearchIsDeterministicUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	for i := 0; i < 30; i++ {
		addEnrolled(t, repo, v, fmt.Sprintf("EMP-%03d", i), 1, synthPoints(30, i))
	}
	g := &gallery{}
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	pts30 := synthPoints(30, 0)
	probe := mcc.BuildTemplate("probe", pts30)
	matcher := mcc.NewMatcher(0.35, 60.0, quietLogger())

	baseline := g.search(ctx, probe, pts30, matcher, 5, quietLogger())
	var wg sync.WaitGroup
	results := make([][]CandidateResult, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = g.search(ctx, probe, pts30, matcher, 5, quietLogger())
		}(i)
	}
	wg.Wait()

	for i, got := range results {
		if len(got) != len(baseline) {
			t.Fatalf("run %d returned %d candidates, baseline returned %d", i, len(got), len(baseline))
		}
		for j := range got {
			if got[j].EmployeeID != baseline[j].EmployeeID || got[j].Score != baseline[j].Score {
				t.Fatalf("run %d position %d = %s/%.4f, baseline = %s/%.4f",
					i, j, got[j].EmployeeID, got[j].Score, baseline[j].EmployeeID, baseline[j].Score)
			}
		}
	}
}

// TestGallery_FindsTheEnrolledFinger is the functional check that the whole
// mechanism still identifies: a probe built from the same points as one
// enrolled finger must surface that employee.
func TestGallery_FindsTheEnrolledFinger(t *testing.T) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)
	addEnrolled(t, repo, v, "TARGET", 1, synthPoints(32, 5))
	for i := 0; i < 8; i++ {
		addEnrolled(t, repo, v, fmt.Sprintf("OTHER-%d", i), 1, synthPoints(32, 100+i))
	}

	g := &gallery{}
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	pts32 := synthPoints(32, 5)
	probe := mcc.BuildTemplate("probe", pts32)
	hits := g.search(ctx, probe, synthPoints(24, 0), mcc.NewMatcher(0.35, 60.0, quietLogger()), 5, quietLogger())

	if len(hits) == 0 {
		t.Fatal("expected the enrolled finger to be identified, got no candidates")
	}
	if hits[0].EmployeeID != "TARGET" {
		t.Fatalf("top candidate was %s, expected TARGET", hits[0].EmployeeID)
	}
}

// Shared helpers for the benchmark file, which lives separately so the
// benchmarks can be skipped without skipping the correctness tests.

func testVaultB(b *testing.B) *crypto.Vault {
	b.Helper()
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		b.Fatalf("new vault: %v", err)
	}
	return v
}

func addEnrolledB(b *testing.B, repo *countingRepo, v *crypto.Vault, empID string, pos int32, points []minutiae.Minutia) {
	b.Helper()
	payload, err := json.Marshal(domain.DecryptedTemplatePayload{
		Minutiae:  points,
		Cylinders: mcc.BuildTemplate(empID, points).Cylinders,
	})
	if err != nil {
		b.Fatal(err)
	}
	ct, err := v.EncryptTemplate(payload)
	if err != nil {
		b.Fatal(err)
	}
	if err := repo.Save(context.Background(), &domain.EnrolledTemplate{
		TemplateID:       empID,
		EmployeeID:       empID,
		Position:         pos,
		EncryptedPayload: ct,
	}); err != nil {
		b.Fatal(err)
	}
}

func empName(i int) string { return fmt.Sprintf("EMP-%05d", i) }
