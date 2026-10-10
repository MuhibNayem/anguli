package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/domain"
)

func newTestRepo(t *testing.T) *Repository {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "lock.db")
	st, err := store.Open(context.Background(), store.Config{Driver: store.DriverSQLite, DSN: dsn})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r, err := New(st)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	return r
}

// TestWithPassEventLock_RunsFnAndCommits is the basic contract: fn runs, and
// whatever it wrote inside the lock is durable once the lock returns.
func TestWithPassEventLock_RunsFnAndCommits(t *testing.T) {
	ctx := context.Background()
	r := newTestRepo(t)

	called := false
	err := r.WithPassEventLock(ctx, "EMP-1", "ZONE-1", func(ctx context.Context) error {
		called = true
		return r.RecordPassEvent(ctx, &domain.PassEvent{
			EmployeeID: "EMP-1", ZoneID: "ZONE-1", Direction: 1, Timestamp: 100,
		})
	})
	if err != nil {
		t.Fatalf("WithPassEventLock: %v", err)
	}
	if !called {
		t.Fatal("fn was not invoked")
	}

	got, err := r.GetLastPassEvent(ctx, "EMP-1", "ZONE-1")
	if err != nil {
		t.Fatalf("event written inside the lock did not survive: %v", err)
	}
	if got.Direction != 1 {
		t.Fatalf("direction = %d, want 1", got.Direction)
	}
}

// TestWithPassEventLock_RollsBackOnError is what keeps a denied evaluation from
// leaving partial state: the insert inside fn must disappear when fn fails.
func TestWithPassEventLock_RollsBackOnError(t *testing.T) {
	ctx := context.Background()
	r := newTestRepo(t)

	sentinel := errors.New("denied by policy")
	err := r.WithPassEventLock(ctx, "EMP-2", "ZONE-1", func(ctx context.Context) error {
		if err := r.RecordPassEvent(ctx, &domain.PassEvent{
			EmployeeID: "EMP-2", ZoneID: "ZONE-1", Direction: 1, Timestamp: 100,
		}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the policy error to propagate, got %v", err)
	}

	// A rolled-back event must not be visible, or a denied swipe would still
	// block the employee's next legitimate entry.
	_, err = r.GetLastPassEvent(ctx, "EMP-2", "ZONE-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back event is still visible: err = %v", err)
	}
}

// TestWithPassEventLock_ExcludesConcurrentWriters is the property the whole
// port method exists for. Ten goroutines each attempt an entry; the lock must
// make them see each other's writes, so at most one can conclude "no prior
// entry".
func TestWithPassEventLock_ExcludesConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	r := newTestRepo(t)

	const n = 10
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var allowed bool
			_ = r.WithPassEventLock(ctx, "EMP-3", "ZONE-1", func(ctx context.Context) error {
				_, err := r.GetLastPassEvent(ctx, "EMP-3", "ZONE-1")
				allowed = errors.Is(err, ErrNotFound)
				if !allowed {
					return nil
				}
				return r.RecordPassEvent(ctx, &domain.PassEvent{
					EmployeeID: "EMP-3", ZoneID: "ZONE-1", Direction: 1, Timestamp: 100,
				})
			})
			if allowed {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if granted != 1 {
		t.Fatalf("%d of %d concurrent writers each saw an empty history; the lock is not exclusive", granted, n)
	}
}

// TestWithPassEventLock_RejectsEmptyKeys keeps an unscoped lock off the table.
// An empty key would collapse every employee into one lock, or with a naive
// implementation into none at all.
func TestWithPassEventLock_RejectsEmptyKeys(t *testing.T) {
	ctx := context.Background()
	r := newTestRepo(t)

	for _, tc := range []struct{ emp, zone string }{
		{"", "ZONE-1"},
		{"EMP-1", ""},
		{"", ""},
	} {
		called := false
		err := r.WithPassEventLock(ctx, tc.emp, tc.zone, func(context.Context) error {
			called = true
			return nil
		})
		if err == nil {
			t.Fatalf("expected an error for emp=%q zone=%q", tc.emp, tc.zone)
		}
		if called {
			t.Fatalf("fn ran despite an invalid lock key emp=%q zone=%q", tc.emp, tc.zone)
		}
	}
}

// TestWithPassEventLock_HonoursContextCancellation checks the lock does not
// ignore a caller that gave up. A request abandoned by its deadline must not
// still be holding the database.
func TestWithPassEventLock_HonoursContextCancellation(t *testing.T) {
	r := newTestRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.WithPassEventLock(ctx, "EMP-4", "ZONE-1", func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("expected an error from a cancelled context, got nil")
	}
}

// TestQueryerFallsBackToPoolOutsideTheLock documents the other half of q():
// with no transaction on the context, calls must go to the pool rather than
// failing to find a queryable at all. Every method depends on this, since the
// non-locked paths are the common case.
func TestQueryerFallsBackToPoolOutsideTheLock(t *testing.T) {
	ctx := context.Background()
	r := newTestRepo(t)

	if _, ok := r.q(ctx).(*sql.DB); !ok {
		t.Fatalf("outside a lock, q() must return the pool, got %T", r.q(ctx))
	}

	// A real round trip proves the pooled path works end to end.
	if err := r.RecordPassEvent(ctx, &domain.PassEvent{
		EmployeeID: "EMP-5", ZoneID: "ZONE-1", Direction: 2, Timestamp: 7,
	}); err != nil {
		t.Fatalf("pooled write: %v", err)
	}
}

// TestQueryerPrefersTheTransaction proves the other direction: inside a lock,
// calls must join the transaction rather than escaping to the pool. A method
// that reached for the pool here would look correctly locked while actually
// running outside it.
func TestQueryerPrefersTheTransaction(t *testing.T) {
	ctx := context.Background()
	r := newTestRepo(t)

	err := r.WithPassEventLock(ctx, "EMP-6", "ZONE-1", func(ctx context.Context) error {
		if _, ok := r.q(ctx).(*sql.Tx); !ok {
			t.Fatalf("inside a lock, q() must return the transaction, got %T", r.q(ctx))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithPassEventLock: %v", err)
	}
}
