package sqlstore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"finger-scanner/pkg/store"
	"finger-scanner/services/biometric-service/internal/domain"
	"finger-scanner/services/biometric-service/internal/ports"
)

// openTemp opens a store in a scratch directory, so a test can close and
// reopen the same file to prove durability.
func openTemp(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(dir, "test.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
		DataDir: dir,
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return st
}

func newRepo(t *testing.T, st *store.Store) *Repository {
	t.Helper()
	r, err := New(st)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sample(id string, pos int32) *domain.EnrolledTemplate {
	return &domain.EnrolledTemplate{
		TemplateID:       "tmpl-" + id,
		EmployeeID:       id,
		FullName:         "Test " + id,
		Position:         pos,
		NFIQScore:        80,
		MinutiaeCount:    24,
		EncryptedPayload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02},
		EnrolledAtUnix:   1700000000,
	}
}

// TestPersistence_SurvivesReopen is the core claim: data written by one
// process is still there for the next. The in-memory adapter could not pass
// this test, and neither could any adapter that keeps state in the process.
func TestPersistence_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	st1 := openTemp(t, dir)
	repo1 := newRepo(t, st1)
	if err := repo1.Save(ctx, sample("EMP-1", 1)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A completely new connection to the same file.
	st2 := openTemp(t, dir)
	defer func() { _ = st2.Close() }()
	repo2 := newRepo(t, st2)

	got, err := repo2.GetByEmployeeAndPosition(ctx, "EMP-1", 1)
	if err != nil {
		t.Fatalf("template did not survive reopen: %v", err)
	}
	if got.TemplateID != "tmpl-EMP-1" || got.NFIQScore != 80 || got.MinutiaeCount != 24 {
		t.Errorf("template corrupted across reopen: %+v", got)
	}
	if string(got.EncryptedPayload) != string([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}) {
		t.Errorf("encrypted payload corrupted across reopen: %v", got.EncryptedPayload)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d; want 1", got.Version)
	}
}

func TestSave_RejectsInvalidInput(t *testing.T) {
	repo := newRepo(t, openTemp(t, t.TempDir()))
	if err := repo.Save(context.Background(), nil); err == nil {
		t.Error("Save(nil) = nil error")
	}
	if err := repo.Save(context.Background(), &domain.EnrolledTemplate{}); err == nil {
		t.Error("Save(template with no EmployeeID) = nil error")
	}
}

func TestGetByEmployeeAndPosition_NotFound(t *testing.T) {
	repo := newRepo(t, openTemp(t, t.TempDir()))
	_, err := repo.GetByEmployeeAndPosition(context.Background(), "NOBODY", 1)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v; want it to wrap store.ErrNotFound", err)
	}
}

func TestSave_ReEnrollBumpsVersionAndArchives(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t, openTemp(t, t.TempDir()))

	first := sample("EMP-2", 1)
	if err := repo.Save(ctx, first); err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 {
		t.Fatalf("first version = %d; want 1", first.Version)
	}

	second := sample("EMP-2", 1)
	second.EnrolledAtUnix = 1700009999
	if err := repo.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 {
		t.Fatalf("second version = %d; want 2 (superseded)", second.Version)
	}

	got, err := repo.GetByEmployeeAndPosition(ctx, "EMP-2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.EnrolledAtUnix != 1700009999 {
		t.Errorf("stored template = %+v; want the newer version", got)
	}

	// The superseded payload must be preserved for audit.
	hist, err := repo.RevocationHistory(ctx, "EMP-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("RevocationHistory returned %d records; want 1", len(hist))
	}
	if hist[0].Reason != "SUPERSEDED_BY_REENROLLMENT" {
		t.Errorf("reason = %q", hist[0].Reason)
	}
	if string(hist[0].PriorPayload) != string([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}) {
		t.Errorf("prior payload not archived intact: %v", hist[0].PriorPayload)
	}
}

func TestSave_DifferentPositionsCoexist(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t, openTemp(t, t.TempDir()))

	for _, pos := range []int32{1, 2, 3, 4, 5} {
		tmpl := sample("EMP-3", pos)
		tmpl.TemplateID = "tmpl-" + string(rune('A'+int(pos)))
		if err := repo.Save(ctx, tmpl); err != nil {
			t.Fatalf("save position %d: %v", pos, err)
		}
	}
	all, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("ListAll returned %d templates; want 5", len(all))
	}
	for _, tmpl := range all {
		if tmpl.EmployeeID != "EMP-3" {
			t.Errorf("unexpected employee %q", tmpl.EmployeeID)
		}
	}
}

func TestListAll_Empty(t *testing.T) {
	repo := newRepo(t, openTemp(t, t.TempDir()))
	all, err := repo.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll on an empty store = %v", err)
	}
	if len(all) != 0 {
		t.Errorf("ListAll returned %d rows on an empty store; want 0", len(all))
	}
}

func TestListAll_OrdersDeterministically(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t, openTemp(t, t.TempDir()))

	for _, id := range []string{"EMP-C", "EMP-A", "EMP-B"} {
		if err := repo.Save(ctx, sample(id, 1)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		all, err := repo.ListAll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if all[0].EmployeeID != "EMP-A" || all[1].EmployeeID != "EMP-B" || all[2].EmployeeID != "EMP-C" {
			t.Fatalf("ListAll order is not deterministic: %v, %v, %v",
				all[0].EmployeeID, all[1].EmployeeID, all[2].EmployeeID)
		}
	}
}

// TestSave_ConcurrentEnrollDoesNotLoseUpdates exercises the transaction: many
// goroutines re-enrolling the same finger must serialise rather than race on
// the version number.
func TestSave_ConcurrentEnrollDoesNotLoseUpdates(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t, openTemp(t, t.TempDir()))

	const n = 25
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tmpl := sample("EMP-RACE", 1)
			tmpl.TemplateID = "tmpl-" + string(rune('a'+i))
			tmpl.EnrolledAtUnix = int64(1700000000 + i)
			errs <- repo.Save(ctx, tmpl)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent save failed: %v", err)
		}
	}

	got, err := repo.GetByEmployeeAndPosition(ctx, "EMP-RACE", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != n {
		t.Errorf("Version = %d after %d enrolls; lost updates", got.Version, n)
	}
}

// TestSatisfiesPort pins that the SQL repository is a drop-in replacement for
// the in-memory one.
func TestSatisfiesPort(t *testing.T) {
	var r ports.TemplateRepository = newRepo(t, openTemp(t, t.TempDir()))
	if r == nil {
		t.Fatal("nil repository")
	}
}

func TestNew_RejectsNilStore(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) = nil error")
	}
}

func TestRecordRevocation(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t, openTemp(t, t.TempDir()))

	if err := repo.RecordRevocation(ctx, nil); err == nil {
		t.Error("RecordRevocation(nil) = nil error")
	}
	rec := &domain.RevocationRecord{
		TemplateID: "t1", EmployeeID: "EMP-4", Position: 2,
		RevokedAtUnix: 1700005000, Reason: "OFFBOARDED",
		PriorPayload: []byte{1, 2, 3},
	}
	if err := repo.RecordRevocation(ctx, rec); err != nil {
		t.Fatal(err)
	}
	hist, err := repo.RevocationHistory(ctx, "EMP-4")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Reason != "OFFBOARDED" {
		t.Fatalf("history = %+v", hist)
	}
}

func TestSchemaVersionRecorded(t *testing.T) {
	st := openTemp(t, t.TempDir())
	defer func() { _ = st.Close() }()

	v, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v == 0 {
		t.Error("SchemaVersion = 0; migrations did not record a version")
	}
}

func TestOpen_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		st := openTemp(t, dir)
		if err := st.Close(); err != nil {
			t.Fatalf("open/close cycle %d: %v", i, err)
		}
	}
}
