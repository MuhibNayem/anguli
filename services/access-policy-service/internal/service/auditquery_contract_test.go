package service_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/adapters/sqlstore"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
)

// The two PolicyRepository adapters must be indistinguishable. A deployment that
// selects STORAGE_DRIVER=memory is running a different system from one on
// SQLite, and for an audit trail that is not an acceptable difference: filters,
// ordering and cursor behaviour all have to match, or an operator's query returns
// different answers depending on which backend a deployment happened to pick.

func bothRepos(t *testing.T) map[string]ports.PolicyRepository {
	t.Helper()

	st, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(t.TempDir(), "policy.db") + "?_pragma=busy_timeout(5000)",
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sqlRepo, err := sqlstore.New(st)
	if err != nil {
		t.Fatalf("new sql repository: %v", err)
	}
	return map[string]ports.PolicyRepository{
		"sqlstore": sqlRepo,
		"memory":   memory.NewMemoryPolicyRepository(),
	}
}

func seedTrail(t *testing.T, repo ports.PolicyRepository) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		e := &domain.AccessAuditEvent{
			EventID:       fmt.Sprintf("e%02d", i),
			TurnstileID:   fmt.Sprintf("t-%d", i%3),
			EmployeeID:    fmt.Sprintf("EMP-%d", i%4),
			ZoneID:        fmt.Sprintf("zone-%d", i%2),
			Decision:      fmt.Sprintf("decision %d", i),
			AccessGranted: i%2 == 0,
			// Two events share a timestamp so the tiebreak is exercised too.
			OccurredUnix: 1700000000 + int64(i/2),
		}
		if _, _, err := repo.RecordAccessEvents(ctx, []*domain.AccessAuditEvent{e}); err != nil {
			t.Fatalf("seed %s: %v", e.EventID, err)
		}
	}
}

// TestAuditQueryAdaptersAgree compares the two adapters filter by filter. Each
// subtest runs the same query against both, so a divergence names itself.
func TestAuditQueryAdaptersAgree(t *testing.T) {
	ctx := context.Background()
	repos := bothRepos(t)

	for name, repo := range repos {
		t.Run(name, func(t *testing.T) { seedTrail(t, repo) })
	}

	cases := []struct {
		name   string
		filter domain.AccessEventFilter
	}{
		{"all", domain.AccessEventFilter{Limit: 100}},
		{"by employee", domain.AccessEventFilter{Limit: 100, EmployeeID: "EMP-1"}},
		{"by zone", domain.AccessEventFilter{Limit: 100, ZoneID: "zone-0"}},
		{"by turnstile", domain.AccessEventFilter{Limit: 100, TurnstileID: "t-1"}},
		{"granted only", domain.AccessEventFilter{Limit: 100, Outcome: domain.OutcomeGranted}},
		{"denied only", domain.AccessEventFilter{Limit: 100, Outcome: domain.OutcomeDenied}},
		{"time window", domain.AccessEventFilter{Limit: 100, FromUnix: 1700000002, ToUnix: 1700000004}},
		{"employee and outcome", domain.AccessEventFilter{Limit: 100, EmployeeID: "EMP-2", Outcome: domain.OutcomeDenied}},
		{"no matches", domain.AccessEventFilter{Limit: 100, EmployeeID: "EMP-nobody"}},
		{"clamped limit", domain.AccessEventFilter{Limit: 1 << 30}},
		{"zero limit", domain.AccessEventFilter{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reference []string
			var referenceUnix int64
			var referenceID string
			for _, name := range []string{"sqlstore", "memory"} {
				events, nextUnix, nextID, err := repos[name].QueryAccessEvents(ctx, tc.filter)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				ids := make([]string, 0, len(events))
				for _, e := range events {
					ids = append(ids, fmt.Sprintf("%s/%v/%v/%d", e.EventID, e.AccessGranted, e.ProcessedOffline, e.OccurredUnix))
				}
				if reference == nil {
					reference = ids
					referenceUnix, referenceID = nextUnix, nextID
					continue
				}
				if len(ids) != len(reference) {
					t.Fatalf("%s returned %d rows, sqlstore returned %d", name, len(ids), len(reference))
				}
				for i := range ids {
					if ids[i] != reference[i] {
						t.Fatalf("row %d: %s returned %s, sqlstore returned %s", i, name, ids[i], reference[i])
					}
				}
				if nextUnix != referenceUnix || nextID != referenceID {
					t.Fatalf("%s cursor is %d/%q, sqlstore cursor is %d/%q",
						name, nextUnix, nextID, referenceUnix, referenceID)
				}
			}
		})
	}
}

// TestAuditPaginationAdaptersAgree walks the whole trail one page at a time
// through both adapters. Filters agreeing is not enough: a cursor that behaves
// differently between backends would silently skip events on exactly the
// deployments that use the in-memory repository.
func TestAuditPaginationAdaptersAgree(t *testing.T) {
	ctx := context.Background()
	repos := bothRepos(t)
	for name, repo := range repos {
		t.Run(name, func(t *testing.T) { seedTrail(t, repo) })
	}

	walk := func(name string, repo ports.PolicyRepository) []string {
		t.Helper()
		var out []string
		filter := domain.AccessEventFilter{Limit: 5}
		var cursorUnix int64
		var cursorID string
		for page := 0; page < 20; page++ {
			filter.CursorUnix, filter.CursorEventID = cursorUnix, cursorID
			events, nextUnix, nextID, err := repo.QueryAccessEvents(ctx, filter)
			if err != nil {
				t.Fatalf("%s page %d: %v", name, page, err)
			}
			for _, e := range events {
				out = append(out, e.EventID)
			}
			if nextID == "" {
				return out
			}
			cursorUnix, cursorID = nextUnix, nextID
		}
		t.Fatalf("%s: pagination did not terminate", name)
		return nil
	}

	sqlSeen := walk("sqlstore", repos["sqlstore"])
	memSeen := walk("memory", repos["memory"])

	if len(sqlSeen) != 12 {
		t.Fatalf("sqlstore paged through %d events, want 12", len(sqlSeen))
	}
	if len(memSeen) != len(sqlSeen) {
		t.Fatalf("memory paged through %d events, sqlstore through %d", len(memSeen), len(sqlSeen))
	}
	seen := map[string]int{}
	for i := range sqlSeen {
		if memSeen[i] != sqlSeen[i] {
			t.Fatalf("page order diverges at %d: memory=%s sqlstore=%s", i, memSeen[i], sqlSeen[i])
		}
		seen[sqlSeen[i]]++
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("event %s returned %d times while paging", id, count)
		}
	}
}
