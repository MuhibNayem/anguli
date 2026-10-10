package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"finger-scanner/pkg/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(t.TempDir(), "s.db") + "?_pragma=busy_timeout(5000)",
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestClaimFacilityIsIdempotent covers the normal boot path: a service restarts
// against its own database and must not fail.
func TestClaimFacilityIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	for i := 0; i < 3; i++ {
		if err := st.ClaimFacility(ctx, "hq-lobby"); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
	got, err := st.FacilityID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hq-lobby" {
		t.Fatalf("facility is %q, want hq-lobby", got)
	}
}

// TestClaimFacilityRefusesAnotherFacility is the guard itself.
//
// Every other table is keyed without a facility, so a database pointed at two
// sites merges their zone policies and employee roles with no error anywhere.
// Reusing a database image or a volume for a second site is a routine operator
// mistake, and it has to fail loudly rather than quietly share access rules.
func TestClaimFacilityRefusesAnotherFacility(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	if err := st.ClaimFacility(ctx, "hq-lobby"); err != nil {
		t.Fatal(err)
	}

	err := st.ClaimFacility(ctx, "warehouse-annex")
	if err == nil {
		t.Fatal("a second facility was allowed to claim a database that belongs to the first; " +
			"two sites would silently share one lobby policy and one set of employee roles")
	}
	if !errors.Is(err, store.ErrFacilityMismatch) {
		t.Fatalf("error is not ErrFacilityMismatch: %v", err)
	}
	// The message has to name both facilities, or an operator cannot act on it.
	for _, want := range []string{"hq-lobby", "warehouse-annex", "STORAGE_DATA_DIR"} {
		if !contains(err.Error(), want) {
			t.Fatalf("error message does not mention %q: %v", want, err)
		}
	}

	// And the original claim must be untouched.
	got, err := st.FacilityID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hq-lobby" {
		t.Fatalf("facility became %q after a refused claim, want hq-lobby", got)
	}
}

// TestClaimFacilityRejectsEmpty guards against the guard silently disabling
// itself. An empty facility would compare equal to every other value, so every
// claim would succeed and the check would look like it was working.
func TestClaimFacilityRejectsEmpty(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	for _, blank := range []string{"", "   "} {
		if err := st.ClaimFacility(ctx, blank); err == nil {
			t.Fatalf("facility %q was accepted; an empty identity makes the guard a no-op", blank)
		}
	}
	id, err := st.FacilityID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Fatalf("a refused empty claim still recorded facility %q", id)
	}
}

// TestFacilityIDIsEmptyBeforeClaiming documents the unclaimed state, which is
// what a freshly migrated database reports.
func TestFacilityIDIsEmptyBeforeClaiming(t *testing.T) {
	st := openStore(t)
	id, err := st.FacilityID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Fatalf("a fresh database reports facility %q, want empty until claimed", id)
	}
}

// TestClaimFacilitySurvivesRestart covers the deployment path: the facility is
// persisted, so a restarted process sees the same identity rather than claiming
// afresh.
func TestClaimFacilitySurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "s.db") + "?_pragma=busy_timeout(5000)"

	st, err := store.Open(ctx, store.Config{Driver: store.DriverSQLite, DSN: dsn, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ClaimFacility(ctx, "hq-lobby"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := store.Open(ctx, store.Config{Driver: store.DriverSQLite, DSN: dsn, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()

	if err := st2.ClaimFacility(ctx, "hq-lobby"); err != nil {
		t.Fatalf("re-claiming the same facility after restart: %v", err)
	}
	if err := st2.ClaimFacility(ctx, "other-site"); err == nil {
		t.Fatal("a restarted process was allowed to re-claim the database for another facility")
	}
}

// TestClaimFacilityIsSafeUnderConcurrentStarts covers two replicas of the same
// service coming up together against one database. Both legitimately claim the
// same facility, and neither may fail or leave the row inconsistent.
func TestClaimFacilityIsSafeUnderConcurrentStarts(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	const replicas = 8
	var wg sync.WaitGroup
	errs := make([]error, replicas)
	start := make(chan struct{})
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = st.ClaimFacility(ctx, "hq-lobby")
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d failed to claim the facility it shares: %v", i, err)
		}
	}
	id, err := st.FacilityID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id != "hq-lobby" {
		t.Fatalf("facility is %q after concurrent claims, want hq-lobby", id)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
