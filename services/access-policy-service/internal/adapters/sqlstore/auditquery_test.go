package sqlstore

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/domain"
)

func auditRepo(t *testing.T) (*Repository, *store.Store) {
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
	r := repoFor(t, st)
	return r, st
}

// seedAudit inserts n events one second apart, oldest first.
func seedAudit(t *testing.T, r *Repository, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		e := auditEvent(fmt.Sprintf("e%d", i))
		e.OccurredUnix = 1700000000 + int64(i)
		e.EmployeeID = "EMP-1"
		e.AccessGranted = i%2 == 0
		if _, _, err := r.RecordAccessEvents(ctx, []*domain.AccessAuditEvent{e}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

// TestQueryAccessEventsReturnsNewestFirst is the ordering an operator expects:
// the most recent door decision is the first row, not the last.
func TestQueryAccessEventsReturnsNewestFirst(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)
	seedAudit(t, r, 10)

	events, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 10 {
		t.Fatalf("returned %d events, want 10", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i-1].OccurredUnix < events[i].OccurredUnix {
			t.Fatalf("results are not newest-first: %d then %d",
				events[i-1].OccurredUnix, events[i].OccurredUnix)
		}
	}
	if events[0].EventID != "e9" {
		t.Fatalf("first row is %s, want the newest event e9", events[0].EventID)
	}
}

// TestQueryAccessEventsFilters is the reason the read path exists at all: an
// audit question is always a filtered one.
func TestQueryAccessEventsFilters(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)
	seedAudit(t, r, 10)

	granted, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 100, Outcome: domain.OutcomeGranted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(granted) != 5 {
		t.Fatalf("granted filter returned %d events, want 5", len(granted))
	}
	for _, e := range granted {
		if !e.AccessGranted {
			t.Fatalf("granted filter returned a denial: %s", e.EventID)
		}
	}

	denied, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 100, Outcome: domain.OutcomeDenied,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 5 {
		t.Fatalf("denied filter returned %d events, want 5", len(denied))
	}

	// A time window bounded on both sides.
	window, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 100, FromUnix: 1700000002, ToUnix: 1700000005,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(window) != 4 {
		t.Fatalf("time window returned %d events, want 4", len(window))
	}

	// A non-matching employee returns nothing rather than everything.
	none, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 100, EmployeeID: "EMP-does-not-exist",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("unknown employee returned %d events, want 0", len(none))
	}
}

// TestQueryAccessEventsPaginatesWithoutGapsOrRepeats is the property that makes
// pagination usable: walking every page must visit each event exactly once.
func TestQueryAccessEventsPaginatesWithoutGapsOrRepeats(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)
	const total = 25
	seedAudit(t, r, total)

	seen := map[string]int{}
	filter := domain.AccessEventFilter{Limit: 7}
	var cursorUnix int64
	var cursorID string
	for page := 0; page < 20; page++ {
		filter.CursorUnix = cursorUnix
		filter.CursorEventID = cursorID
		events, nextUnix, nextID, err := r.QueryAccessEvents(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			seen[e.EventID]++
		}
		if nextID == "" {
			break
		}
		cursorUnix, cursorID = nextUnix, nextID
	}

	if len(seen) != total {
		t.Fatalf("paging visited %d distinct events, want %d; a page was skipped", len(seen), total)
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("event %s was returned %d times across pages", id, count)
		}
	}
}

// TestQueryAccessEventsCursorSurvivesNewArrivals is why this paginates by
// keyset rather than by offset.
//
// A replay arriving mid-scan is normal, not exceptional: edges flush on a timer.
// With an offset cursor, inserting rows at the head shifts every later page and
// the operator silently misses events - which during an investigation looks
// exactly like the person never having entered.
func TestQueryAccessEventsCursorSurvivesNewArrivals(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)
	seedAudit(t, r, 10)

	first, nextUnix, nextID, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 5 || nextID == "" {
		t.Fatalf("first page returned %d events with cursor %q", len(first), nextID)
	}

	// A replay lands newer than everything read so far, between the pages.
	for _, id := range []string{"x1", "x2"} {
		e := auditEvent(id)
		e.OccurredUnix = 1700000500
		e.EmployeeID = "EMP-1"
		if _, _, err := r.RecordAccessEvents(ctx, []*domain.AccessAuditEvent{e}); err != nil {
			t.Fatal(err)
		}
	}

	second, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 100, CursorUnix: nextUnix, CursorEventID: nextID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range second {
		for _, prev := range first {
			if e.EventID == prev.EventID {
				t.Fatalf("event %s reappeared on the second page after a concurrent insert", e.EventID)
			}
		}
	}
	// The five that were not yet read must all still be there.
	if len(second) != 5 {
		t.Fatalf("second page returned %d events, want the 5 not yet read", len(second))
	}
}

// TestQueryAccessEventsClampsLimit keeps one caller from asking for a site's
// entire history in a single response.
func TestQueryAccessEventsClampsLimit(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)
	seedAudit(t, r, 5)

	events, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{Limit: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) > domain.MaxAuditQueryLimit {
		t.Fatalf("limit was not clamped: got %d events, cap is %d", len(events), domain.MaxAuditQueryLimit)
	}

	// Zero selects the default rather than returning everything.
	none, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) > domain.DefaultAuditQueryLimit {
		t.Fatalf("zero limit returned %d events, default cap is %d", len(none), domain.DefaultAuditQueryLimit)
	}
}

// TestQueryAccessEventsBreaksTiesOnTimestamp covers several events landing in
// the same second. Without a total order the cursor cannot express a position
// between them, and paging either skips one or repeats it forever.
func TestQueryAccessEventsBreaksTiesOnTimestamp(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)

	events := make([]*domain.AccessAuditEvent, 0, 6)
	for _, id := range []string{"b", "a", "c", "e", "d", "f"} {
		e := auditEvent(id)
		e.OccurredUnix = 1700000000 // all identical
		e.EmployeeID = "EMP-1"
		events = append(events, e)
	}
	if _, _, err := r.RecordAccessEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	filter := domain.AccessEventFilter{Limit: 2}
	var cursorUnix int64
	var cursorID string
	for page := 0; page < 10; page++ {
		filter.CursorUnix, filter.CursorEventID = cursorUnix, cursorID
		batch, nextUnix, nextID, err := r.QueryAccessEvents(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range batch {
			seen[e.EventID]++
		}
		if nextID == "" {
			break
		}
		cursorUnix, cursorID = nextUnix, nextID
	}

	if len(seen) != 6 {
		t.Fatalf("same-second events: paging visited %d of 6", len(seen))
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("same-second event %s returned %d times", id, count)
		}
	}
}

// TestQueryAccessEventsFiltersAreParameterised guards the SQL assembly. Every
// caller-supplied value must be a bound parameter, so a hostile employee id
// cannot alter the query.
func TestQueryAccessEventsFiltersAreParameterised(t *testing.T) {
	ctx := context.Background()
	r, _ := auditRepo(t)

	hostile := "EMP-1'; DROP TABLE access_audit_events; --"
	e := auditEvent("inject")
	e.EmployeeID = hostile
	if _, _, err := r.RecordAccessEvents(ctx, []*domain.AccessAuditEvent{e}); err != nil {
		t.Fatal(err)
	}

	got, _, _, err := r.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 10, EmployeeID: hostile,
	})
	if err != nil {
		t.Fatalf("query with a quote-bearing filter failed: %v", err)
	}
	if len(got) != 1 || got[0].EmployeeID != hostile {
		t.Fatalf("filter returned %d rows, want the single matching row", len(got))
	}

	// The table must still exist.
	var total int
	if err := r.st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM access_audit_events`).Scan(&total); err != nil {
		t.Fatalf("access_audit_events is gone: %v", err)
	}
	if total != 1 {
		t.Fatalf("table holds %d rows, want 1", total)
	}
}
