package sqlstore

import (
	"context"
	"path/filepath"
	"testing"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/domain"
)

// repoFor builds a repository over an already-open store, so a test can
// reopen the same database file and prove durability across a restart.
func repoFor(t *testing.T, st *store.Store) *Repository {
	t.Helper()
	r, err := New(st)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	return r
}

// newPolicyRepo opens a file-backed SQLite store (not :memory:) so the
// durability test can reopen the same file.
func newPolicyRepo(t *testing.T) (*Repository, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(dir, "policy.db") + "?_pragma=busy_timeout(5000)",
		DataDir: dir,
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return repoFor(t, st), st
}

func auditEvent(id string) *domain.AccessAuditEvent {
	return &domain.AccessAuditEvent{
		EventID:          id,
		TurnstileID:      "turnstile-01",
		EmployeeID:       "EMP-1",
		ZoneID:           "zone-main-gate",
		Decision:         "Access granted",
		AccessGranted:    true,
		ProcessedOffline: true,
		OccurredUnix:     1700000000,
	}
}

// TestRecordAccessEventsIsIdempotent is the property that makes a replayed
// batch safe.
//
// An edge that fails partway through forwarding cannot know which rows
// upstream committed before the connection dropped, so it retries the whole
// batch. Without deduplication on event_id, one interrupted replay would
// double every door entry it contained - and a duplicated audit trail is worse
// than a missing one, because it destroys trust in the whole log.
func TestRecordAccessEventsIsIdempotent(t *testing.T) {
	ctx := context.Background()
	r, st := newPolicyRepo(t)

	batch := []*domain.AccessAuditEvent{auditEvent("e1"), auditEvent("e2"), auditEvent("e3")}

	recorded, dup, err := r.RecordAccessEvents(ctx, batch)
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	if recorded != 3 || dup != 0 {
		t.Fatalf("first batch recorded=%d duplicates=%d, want 3 and 0", recorded, dup)
	}

	// Exact retry, which is what the edge does after a partial failure.
	recorded, dup, err = r.RecordAccessEvents(ctx, batch)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if recorded != 0 || dup != 3 {
		t.Fatalf("retry recorded=%d duplicates=%d, want 0 and 3", recorded, dup)
	}

	// Partially overlapping batch: a mix of new and already-seen events.
	mixed := append([]*domain.AccessAuditEvent{auditEvent("e4")}, batch...)
	recorded, dup, err = r.RecordAccessEvents(ctx, mixed)
	if err != nil {
		t.Fatalf("mixed batch: %v", err)
	}
	if recorded != 1 || dup != 3 {
		t.Fatalf("mixed batch recorded=%d duplicates=%d, want 1 and 3", recorded, dup)
	}

	var total int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM access_audit_events`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("access_audit_events holds %d rows, want 4; retries duplicated door entries", total)
	}
}

func TestRecordAccessEventsEmptyBatch(t *testing.T) {
	ctx := context.Background()
	r, _ := newPolicyRepo(t)

	recorded, dup, err := r.RecordAccessEvents(ctx, nil)
	if err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if recorded != 0 || dup != 0 {
		t.Fatalf("empty batch recorded=%d duplicates=%d", recorded, dup)
	}
}

// TestRecordAccessEventsSkipsUnidentifiableEvents covers the case where the
// edge produced an event with no id. It cannot be deduplicated, so storing it
// would create a row that any retry duplicates. Skipping it is the honest
// choice; it is counted so the caller can notice.
func TestRecordAccessEventsSkipsUnidentifiableEvents(t *testing.T) {
	ctx := context.Background()
	r, _ := newPolicyRepo(t)

	batch := []*domain.AccessAuditEvent{auditEvent("e1"), {EventID: ""}, nil}

	recorded, dup, err := r.RecordAccessEvents(ctx, batch)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if recorded != 1 || dup != 2 {
		t.Fatalf("recorded=%d duplicates=%d, want 1 and 2", recorded, dup)
	}
}

// TestRecordAccessEventsSurvivesRestart confirms the audit trail is durable
// rather than in-memory: central storage is the whole point of this table.
func TestRecordAccessEventsSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	st, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(dir, "policy.db") + "?_pragma=busy_timeout(5000)",
		DataDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repoFor(t, st).RecordAccessEvents(ctx, []*domain.AccessAuditEvent{auditEvent("e1")}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(dir, "policy.db") + "?_pragma=busy_timeout(5000)",
		DataDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()

	var employee string
	var granted int
	err = st2.DB().QueryRowContext(ctx,
		`SELECT employee_id, access_granted FROM access_audit_events WHERE event_id = ?`, "e1",
	).Scan(&employee, &granted)
	if err != nil {
		t.Fatalf("recorded event did not survive restart: %v", err)
	}
	if employee != "EMP-1" || granted != 1 {
		t.Fatalf("event survived as employee=%q granted=%d, want EMP-1 and 1", employee, granted)
	}
}
