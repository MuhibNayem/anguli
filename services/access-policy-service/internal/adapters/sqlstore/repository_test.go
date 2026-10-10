package sqlstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
)

func newRepo(t *testing.T) (*Repository, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r, err := New(st)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	return r, st
}

func TestNewRejectsNilStore(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) succeeded")
	}
}

func TestSaveAndGetRule(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()

	want := &domain.PolicyRule{
		ZoneID:                "lobby",
		AllowedRole:           "EMPLOYEE",
		RequireBiometrics:     true,
		MinBiometricScore:     42.5,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 90,
	}
	if err := r.SaveRule(ctx, want); err != nil {
		t.Fatalf("SaveRule: %v", err)
	}
	got, err := r.GetRule(ctx, "lobby")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if *got != *want {
		t.Errorf("got %+v; want %+v", got, want)
	}

	// A second save must overwrite, not duplicate or conflict.
	want.MinBiometricScore = 60
	if err := r.SaveRule(ctx, want); err != nil {
		t.Fatalf("second SaveRule: %v", err)
	}
	got, err = r.GetRule(ctx, "lobby")
	if err != nil {
		t.Fatal(err)
	}
	if got.MinBiometricScore != 60 {
		t.Errorf("min score = %v after update; want 60", got.MinBiometricScore)
	}
}

func TestGetRuleNotFound(t *testing.T) {
	r, _ := newRepo(t)
	if _, err := r.GetRule(context.Background(), "nowhere"); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("err = %v; want ports.ErrNotFound", err)
	}
}

func TestSaveRuleRejectsBadInput(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	if err := r.SaveRule(ctx, nil); err == nil {
		t.Error("SaveRule(nil) succeeded")
	}
	if err := r.SaveRule(ctx, &domain.PolicyRule{}); err == nil {
		t.Error("SaveRule with an empty zone succeeded")
	}
}

func TestPassEventsAreAppendOnlyAndOrdered(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()

	base := int64(1_700_000_000)
	for i := 0; i < 3; i++ {
		if err := r.RecordPassEvent(ctx, &domain.PassEvent{
			EmployeeID: "emp-1",
			ZoneID:     "lobby",
			DoorID:     "lane-1",
			Direction:  1 + int32(i%2),
			Timestamp:  base + int64(i),
		}); err != nil {
			t.Fatalf("RecordPassEvent %d: %v", i, err)
		}
	}
	last, err := r.GetLastPassEvent(ctx, "emp-1", "lobby")
	if err != nil {
		t.Fatalf("GetLastPassEvent: %v", err)
	}
	if last.Timestamp != base+2 {
		t.Errorf("last timestamp = %d; want %d (the newest)", last.Timestamp, base+2)
	}
	if last.DoorID != "lane-1" {
		t.Errorf("door = %q", last.DoorID)
	}
}

// This is the assertion behind the durable-policy decision. Two repositories
// over the SAME database - which is what two Kubernetes replicas are - must see
// each other's events. With a per-process map they cannot, and anti-passback
// silently stops applying the moment a second replica exists.
func TestTwoRepositoriesShareState(t *testing.T) {
	r1, st := newRepo(t)
	r2, err := New(st)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := r1.RecordPassEvent(ctx, &domain.PassEvent{
		EmployeeID: "emp-7", ZoneID: "lobby", DoorID: "lane-1",
		Direction: 1, Timestamp: 1_700_000_000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := r1.SaveRule(ctx, &domain.PolicyRule{ZoneID: "lobby", EnforceAntiPassback: true}); err != nil {
		t.Fatal(err)
	}

	// The second "replica" must see both.
	if _, err := r2.GetLastPassEvent(ctx, "emp-7", "lobby"); err != nil {
		t.Fatalf("the second repository cannot see the first's pass event: %v", err)
	}
	if _, err := r2.GetRule(ctx, "lobby"); err != nil {
		t.Fatalf("the second repository cannot see the first's rule: %v", err)
	}

	// And a reset performed on one is visible to the other.
	if err := r2.ResetAntiPassback(ctx, "emp-7", "lobby"); err != nil {
		t.Fatal(err)
	}
	last, err := r1.GetLastPassEvent(ctx, "emp-7", "lobby")
	if err != nil {
		t.Fatal(err)
	}
	if last.Direction != 2 {
		t.Errorf("direction after reset = %d; want 2 (an exit), so anti-passback is cleared", last.Direction)
	}
}

// Reset must not erase the audit trail. Destroying the access log to implement
// an administrative override is the wrong trade in a system whose log is the
// record of who went where.
func TestResetKeepsHistory(t *testing.T) {
	r, st := newRepo(t)
	ctx := context.Background()

	if err := r.RecordPassEvent(ctx, &domain.PassEvent{
		EmployeeID: "emp-1", ZoneID: "lobby", Direction: 1, Timestamp: 1_700_000_000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.ResetAntiPassback(ctx, "emp-1", "lobby"); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pass_events WHERE employee_id = ?`, "emp-1").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("pass_events rows = %d after a reset; want 2 (the original is retained)", n)
	}
}

func TestGetLastPassEventNotFound(t *testing.T) {
	r, _ := newRepo(t)
	_, err := r.GetLastPassEvent(context.Background(), "nobody", "lobby")
	if !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("err = %v; want ports.ErrNotFound", err)
	}
	// Must NOT be (nil, nil): the service has to be able to tell a first-ever
	// visit apart from a storage fault.
}

func TestRecordPassEventRejectsBadInput(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	if err := r.RecordPassEvent(ctx, nil); err == nil {
		t.Error("RecordPassEvent(nil) succeeded")
	}
	if err := r.RecordPassEvent(ctx, &domain.PassEvent{ZoneID: "lobby"}); err == nil {
		t.Error("RecordPassEvent with no employee succeeded")
	}
}

// A zero timestamp means "now"; storing literal zero would make every such
// event sort as the oldest row forever and defeat the anti-passback window.
func TestRecordPassEventDefaultsTimestamp(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()
	before := time.Now().Unix()

	if err := r.RecordPassEvent(ctx, &domain.PassEvent{
		EmployeeID: "emp-1", ZoneID: "lobby", Direction: 1,
	}); err != nil {
		t.Fatal(err)
	}
	last, err := r.GetLastPassEvent(ctx, "emp-1", "lobby")
	if err != nil {
		t.Fatal(err)
	}
	if last.Timestamp < before-5 {
		t.Errorf("timestamp = %d; want ~now (%d)", last.Timestamp, before)
	}
}

func TestEmployeeRoles(t *testing.T) {
	r, _ := newRepo(t)
	ctx := context.Background()

	if _, err := r.GetEmployeeRole(ctx, "emp-1"); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("err = %v; want ports.ErrNotFound", err)
	}
	if err := r.SetEmployeeRole(ctx, "emp-1", "SECURITY"); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetEmployeeRole(ctx, "emp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "SECURITY" {
		t.Errorf("role = %q; want SECURITY", got)
	}
	if err := r.SetEmployeeRole(ctx, "emp-1", "STAFF"); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetEmployeeRole(ctx, "emp-1")
	if got != "STAFF" {
		t.Errorf("role after update = %q; want STAFF", got)
	}
	if err := r.SetEmployeeRole(ctx, "", "STAFF"); err == nil {
		t.Error("SetEmployeeRole with an empty id succeeded")
	}
}

// Migrate runs on every boot, so it must be idempotent.
func TestMigrateIsIdempotent(t *testing.T) {
	_, st := newRepo(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := st.Migrate(ctx); err != nil {
			t.Fatalf("Migrate run %d: %v", i, err)
		}
	}
	v, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("schema version = %d; want 1", v)
	}
}

func TestSQLiteFileIsCreatedUnderDataDir(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(context.Background(), store.Config{
		Driver: store.DriverSQLite, DataDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.DSN() == "" {
		t.Error("DSN is empty")
	}
	if !filepath.IsAbs(st.DSN()) && st.DSN() != "" {
		// Not a hard requirement, but a relative DSN would put the database
		// somewhere the working directory decides, which is how two replicas
		// end up with two databases.
		t.Logf("DSN is relative: %q", st.DSN())
	}
}
