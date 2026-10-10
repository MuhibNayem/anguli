package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"finger-scanner/pkg/store"
)

// txKey scopes a transaction to a context.
//
// It is unexported and typed, so nothing outside this package can collide with
// it. This is the standard way to make a transaction invisible to repository
// method signatures: without it every method would need a "tx or db" parameter
// threaded through the port, which would leak transaction management into the
// service and make forgetting to pass it the easy mistake.
type txKey struct{}

// withTx stores tx on the context.
func withTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// queryer is satisfied by both *sql.DB and *sql.Tx, which is what lets one
// method body serve both the locked and the unlocked path.
type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// q returns the transaction bound to ctx, or the pool when there is none.
//
// Every read and write in this repository goes through here. A method that
// reached for r.st.DB() directly while a pass-event lock was held would run
// outside the transaction and outside the lock's protection, which would make
// the locking look correct while providing no exclusion at all.
func (r *Repository) q(ctx context.Context) queryer {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok && tx != nil {
		return tx
	}
	return r.st.DB()
}

// keyedMutex is a set of mutexes addressed by string, created on demand.
//
// Entries are never reclaimed. That is deliberate: this guards one key per
// (employee, zone) that has ever taken a pass, and a lock map that shrinks
// under concurrency can hand the same key to two goroutines at once, which is
// the bug this type exists to prevent. The cost is bounded by the number of
// distinct employees who have ever crossed the door.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func newKeyedMutex() *keyedMutex { return &keyedMutex{m: make(map[string]*sync.Mutex)} }

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	mu, ok := k.m[key]
	if !ok {
		mu = &sync.Mutex{}
		k.m[key] = mu
	}
	k.mu.Unlock()

	mu.Lock()
	return mu.Unlock
}

// WithPassEventLock serialises the anti-passback check-and-record for one
// (employee, zone) pair.
//
// Postgres is the case that matters, because that is the driver a multi-replica
// deployment selects. A transaction-scoped advisory lock keyed by a hash of the
// pair makes two replicas queue at the database rather than in local memory:
// the second one re-reads the state the first one committed instead of the
// stale state it saw before blocking. Without it, two concurrent transactions
// both read "no prior entry" and both commit, because default READ COMMITTED
// does not conflict two read-then-write transactions that touch different
// rows. The lock is released automatically at COMMIT or ROLLBACK, so no early
// return or panic can leak it.
//
// SQLite is single-node by contract - the Helm chart refuses more than one
// replica on it - so a process-local keyed mutex is the whole of the exclusion
// needed, and the transaction around it supplies atomicity and rollback. It
// would not be sufficient for two processes sharing one file, which is why the
// multi-replica path is required to use Postgres rather than because this code
// makes SQLite safe to share.
func (r *Repository) WithPassEventLock(ctx context.Context, employeeID, zoneID string, fn func(context.Context) error) error {
	if employeeID == "" || zoneID == "" {
		return errors.New("sqlstore: pass-event lock requires a non-empty employee and zone")
	}

	if r.st.Driver() != store.DriverPostgres {
		unlock := r.locks.lock(employeeID + ":" + zoneID)
		defer unlock()
	}

	tx, err := r.st.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: begin pass-event transaction: %w", err)
	}

	if r.st.Driver() == store.DriverPostgres {
		// hashtext collapses the pair to a 32-bit key, which is the documented
		// form for pg_advisory_xact_lock. A collision serialises two unrelated
		// employees for the duration of one decision; it can never permit a
		// concurrent write.
		if _, err := tx.ExecContext(ctx, r.st.Rebind(
			`SELECT pg_advisory_xact_lock(hashtext(?))`), employeeID+":"+zoneID); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlstore: acquire anti-passback advisory lock for %s at %s: %w", employeeID, zoneID, err)
		}
	}

	if err := fn(withTx(ctx, tx)); err != nil {
		// Roll back so a denied evaluation leaves no partial state, and so
		// both the advisory lock and the SQLite write lock are released.
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqlstore: commit pass-event transaction: %w", err)
	}
	return nil
}
