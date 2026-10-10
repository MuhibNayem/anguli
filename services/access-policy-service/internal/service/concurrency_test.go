package service_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/adapters/sqlstore"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
	"finger-scanner/services/access-policy-service/internal/service"
)

// slowRepo inserts a realistic delay into the window between the anti-passback
// read and the write, and can optionally disable locking entirely.
//
// The delay is the point. Without it these tests measure nothing: on a
// in-memory map the gap between GetLastPassEvent returning and RecordPassEvent
// being called is a few nanoseconds, and goroutines rarely land inside it. An
// unlocked repository was measured admitting exactly 1 of 16 attempts - the
// same answer a correctly locked one gives - purely by luck. That is the trap
// this wrapper exists to defuse.
//
// The delay stands in for what is actually in that window in production: a
// database round trip, a TLS handshake cost, an admission-queue wait. The race
// is not a theoretical interleaving; it is what happens when the read and the
// write are separated by I/O.
type slowRepo struct {
	ports.PolicyRepository
	delay  time.Duration
	unlock bool // when true, WithPassEventLock is a no-op
}

func (s slowRepo) GetLastPassEvent(ctx context.Context, empID, zoneID string) (*domain.PassEvent, error) {
	ev, err := s.PolicyRepository.GetLastPassEvent(ctx, empID, zoneID)
	time.Sleep(s.delay)
	return ev, err
}

func (s slowRepo) WithPassEventLock(ctx context.Context, empID, zoneID string, fn func(context.Context) error) error {
	if s.unlock {
		return fn(ctx)
	}
	return s.PolicyRepository.WithPassEventLock(ctx, empID, zoneID, fn)
}

// runConcurrentEntries fires n simultaneous ENTRY evaluations for one employee
// at one zone and returns how many were granted.
func runConcurrentEntries(t *testing.T, repo ports.PolicyRepository, n int) int {
	t.Helper()
	svc := service.NewPolicyService(repo, nil)

	// A closed start line: every goroutine blocks on this channel before it
	// touches the repository, so they genuinely contend rather than trickling
	// in and each finding the previous one's already-committed state.
	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})

	var wg sync.WaitGroup
	granted := make([]bool, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ready.Done()
			<-start
			res, err := svc.Evaluate(context.Background(),
				"EMP-RACE-001", "zone-main-gate", "door-01", 1 /* Entry */, true, 80.0)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			granted[i] = res.IsGranted
		}(i)
	}
	ready.Wait()
	close(start)
	wg.Wait()

	count := 0
	for _, g := range granted {
		if g {
			count++
		}
	}
	return count
}

func newSQLRepo(t *testing.T) ports.PolicyRepository {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "apb.db")
	st, err := store.Open(context.Background(), store.Config{Driver: store.DriverSQLite, DSN: dsn})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r, err := sqlstore.New(st)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	return r
}

// withAPBZone configures an anti-passback zone explicitly on repo.
//
// Both adapters are configured rather than relying on seed data. The memory
// adapter happens to ship zone-main-gate preconfigured; the SQL adapter does
// not, and correctly fails closed on an unconfigured zone - so a test that
// assumed the seed would silently measure the deny-on-unknown-zone path and
// report "0 admitted", which looks like a locking failure and is not one.
func withAPBZone(t *testing.T, repo ports.PolicyRepository) ports.PolicyRepository {
	t.Helper()
	rule := &domain.PolicyRule{
		ZoneID:                "zone-main-gate",
		AllowedRole:           "EMPLOYEE",
		RequireBiometrics:     true,
		MinBiometricScore:     60.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	}
	if err := repo.SaveRule(context.Background(), rule); err != nil {
		t.Fatalf("configure zone: %v", err)
	}
	return repo
}

// TestPolicyService_ConcurrentEntryAdmitsExactlyOne is the regression test for
// the anti-passback TOCTOU race.
//
// The defect was that GetLastPassEvent and RecordPassEvent were separate calls.
// Two turnstiles served by different replicas could both read "no prior entry"
// in the same instant and both be admitted, which is the precise event the rule
// exists to prevent. Durable storage fixed visibility of the state but not
// exclusivity of the decision.
//
// Exactly one of N simultaneous ENTRY attempts may be granted. Asserting the
// exact number rather than "at most one" is deliberate: a repository that
// admitted nobody would also satisfy the weaker assertion, and a door that
// never opens is not a correct anti-passback either.
func TestPolicyService_ConcurrentEntryAdmitsExactlyOne(t *testing.T) {
	const attempts = 12
	const delay = 5 * time.Millisecond

	for _, tc := range []struct {
		name string
		repo ports.PolicyRepository
	}{
		{"memory", slowRepo{PolicyRepository: withAPBZone(t, memory.NewMemoryPolicyRepository()), delay: delay}},
		{"sqlite", slowRepo{PolicyRepository: withAPBZone(t, newSQLRepo(t)), delay: delay}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runConcurrentEntries(t, tc.repo, attempts); got != 1 {
				t.Fatalf("anti-passback admitted %d of %d simultaneous entries; exactly 1 is correct", got, attempts)
			}
		})
	}
}

// TestPolicyService_ConcurrencyTestIsDiscriminating proves the test above is
// measuring exclusion rather than luck.
//
// It runs the identical scenario against a repository whose locking is a
// no-op and asserts the race actually fires. Without this, the positive test
// could be green for the wrong reason - and it was: with no injected delay an
// unlocked repository also admitted exactly 1 of 16, so that version of the
// test proved nothing at all.
//
// If this test ever fails, the positive test has stopped overlapping the calls
// and must be rewritten rather than trusted.
func TestPolicyService_ConcurrencyTestIsDiscriminating(t *testing.T) {
	const attempts = 12
	const delay = 5 * time.Millisecond

	unlocked := slowRepo{
		PolicyRepository: withAPBZone(t, memory.NewMemoryPolicyRepository()),
		delay:            delay,
		unlock:           true,
	}
	if got := runConcurrentEntries(t, unlocked, attempts); got <= 1 {
		t.Fatalf("unlocked repository admitted only %d of %d; the concurrency "+
			"test is not exercising the race and proves nothing", got, attempts)
	}
}
