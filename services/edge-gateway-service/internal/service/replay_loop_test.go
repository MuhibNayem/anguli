package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"finger-scanner/services/edge-gateway-service/internal/domain"
)

// countingSvc records how many times the loop asked for a replay and lets a test
// make each attempt succeed or fail.
type countingSvc struct {
	mu      sync.Mutex
	calls   int
	err     error
	events  int
	waiters chan struct{}
}

func (c *countingSvc) ReplayEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error) {
	c.mu.Lock()
	c.calls++
	n := c.events
	err := c.err
	c.mu.Unlock()
	select {
	case c.waiters <- struct{}{}:
	default:
	}
	if err != nil {
		return nil, err
	}
	return make([]*domain.OfflineAuditLog, n), nil
}

func (c *countingSvc) ProcessScan(context.Context, string, string, int32, string, []byte, uint32, uint32) (*ScanResult, error) {
	return nil, errors.New("not implemented")
}
func (c *countingSvc) SyncRoster(context.Context, []*domain.CachedEmployee) (uint32, error) {
	return 0, errors.New("not implemented")
}
func (c *countingSvc) SyncPolicies(context.Context, []*domain.PolicyRule) error {
	return errors.New("not implemented")
}
func (c *countingSvc) GetStatus(context.Context, string) (*domain.TurnstileState, error) {
	return nil, errors.New("not implemented")
}

func (c *countingSvc) snapshot() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func waitForCalls(t *testing.T, c *countingSvc, want int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for c.snapshot() < want {
		select {
		case <-c.waiters:
		case <-deadline:
			t.Fatalf("replay loop made %d attempts, want at least %d; it is not replaying on its own",
				c.snapshot(), want)
		}
	}
}

// TestOfflineReplayLoopReplaysWithoutBeingAsked is the property this loop
// exists to provide.
//
// ReplayEvents was correct and reachable through a gRPC endpoint, but no running
// process ever called it. The edge buffered every door decision during an outage
// and never sent any of them, so central storage had no access trail at all and
// the only copy sat on one machine's disk. Nothing here polls or inspects the
// service; it only asserts that the loop drives replays on its own.
func TestOfflineReplayLoopReplaysWithoutBeingAsked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &countingSvc{events: 3, waiters: make(chan struct{}, 64)}
	go RunOfflineReplayLoop(ctx, svc, 10*time.Millisecond, quietLogger())

	// The immediate attempt plus at least two ticks.
	waitForCalls(t, svc, 3)
	cancel()
}

// TestOfflineReplayLoopReplaysImmediatelyOnStart covers the reboot case: a node
// that comes back after an outage holds a backlog, and waiting a full interval
// before flushing it just extends the window where central has no record.
func TestOfflineReplayLoopReplaysImmediatelyOnStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// An interval far longer than the test: only an immediate attempt can
	// produce a call.
	svc := &countingSvc{waiters: make(chan struct{}, 8)}
	go RunOfflineReplayLoop(ctx, svc, time.Hour, quietLogger())

	waitForCalls(t, svc, 1)
}

// TestOfflineReplayLoopKeepsRetryingThroughAnOutage confirms a transient failure
// does not permanently stop the flush. A loop that quit on first error would
// leave the audit trail stranded for the life of the process.
func TestOfflineReplayLoopKeepsRetryingThroughAnOutage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &countingSvc{err: errors.New("policy unreachable"), waiters: make(chan struct{}, 64)}
	go RunOfflineReplayLoop(ctx, svc, 10*time.Millisecond, quietLogger())

	waitForCalls(t, svc, 4)
}

// TestOfflineReplayLoopStopsOnShutdown makes sure the goroutine does not outlive
// the process and hold the service open during a graceful stop.
func TestOfflineReplayLoopStopsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	svc := &countingSvc{waiters: make(chan struct{}, 64)}
	done := make(chan struct{})
	go func() {
		RunOfflineReplayLoop(ctx, svc, 5*time.Millisecond, quietLogger())
		close(done)
	}()

	waitForCalls(t, svc, 1)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("replay loop did not stop when its context was cancelled")
	}

	before := svc.snapshot()
	time.Sleep(50 * time.Millisecond)
	if after := svc.snapshot(); after != before {
		t.Fatalf("replay loop kept running after cancellation: %d calls before, %d after", before, after)
	}
}

// TestOfflineReplayLoopSurvivesCancellationDuringFailure guards the shutdown
// path: a replay aborted by shutdown is not an incident, and it must neither
// panic nor spin.
func TestOfflineReplayLoopSurvivesCancellationDuringFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	svc := &countingSvc{err: context.Canceled, waiters: make(chan struct{}, 64)}
	done := make(chan struct{})
	go func() {
		RunOfflineReplayLoop(ctx, svc, 5*time.Millisecond, quietLogger())
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("replay loop did not stop after cancellation during a failing replay")
	}
}

// TestOfflineReplayLoopRejectsNilService keeps a wiring mistake from panicking
// the daemon at startup.
func TestOfflineReplayLoopRejectsNilService(t *testing.T) {
	RunOfflineReplayLoop(context.Background(), nil, time.Millisecond, slog.Default())
}

// TestOfflineReplayLoopDefaultsNonPositiveInterval covers the case where a
// deployment passes 0 or a negative duration. Falling back to the default keeps
// the flush running; treating 0 as "disabled" would quietly recreate the gap.
func TestOfflineReplayLoopDefaultsNonPositiveInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &countingSvc{waiters: make(chan struct{}, 8)}
	done := make(chan struct{})
	go func() {
		RunOfflineReplayLoop(ctx, svc, 0, quietLogger())
		close(done)
	}()

	// The immediate attempt must still happen.
	waitForCalls(t, svc, 1)
	cancel()
	<-done
}
