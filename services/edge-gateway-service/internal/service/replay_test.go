package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/ports"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stubPolicy records what the edge forwarded upstream and can be made to fail,
// which is how the "forward failed" paths are exercised.
type stubPolicy struct {
	accesscontrolv1.AccessPolicyServiceClient
	batches [][]*accesscontrolv1.AccessAuditEvent
	err     error
}

func (s *stubPolicy) RecordAccessEvents(
	_ context.Context, in *accesscontrolv1.RecordAccessEventsRequest, _ ...grpc.CallOption,
) (*accesscontrolv1.RecordAccessEventsResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.batches = append(s.batches, in.GetEvents())
	return &accesscontrolv1.RecordAccessEventsResponse{
		Recorded: uint32(len(in.GetEvents())),
	}, nil
}

func newCache(t *testing.T) (ports.EdgeRepository, string) {
	t.Helper()
	wal := filepath.Join(t.TempDir(), "audit.wal")
	return memory.NewDurableEdgeCache(wal), wal
}

func seed(t *testing.T, c ports.EdgeRepository, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := c.AppendOfflineEvent(context.Background(), &domain.OfflineAuditLog{
			EventID:       "evt-" + string(rune('a'+i)),
			TurnstileID:   "t-1",
			EmployeeID:    "EMP-1",
			ZoneID:        "zone-main-gate",
			AccessGranted: true,
			Decision:      "granted",
			TimestampUnix: 1700000000 + int64(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func walLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}
	var out []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, string(data[start:i]))
			start = i + 1
		}
	}
	return out
}

// TestReplayKeepsEventsAppendedDuringTheForward covers a door that opens while
// the replay is already in flight.
//
// The queue is emptied up front, so a scan landing mid-forward is the only copy
// of that event - in memory and on disk. Retiring the batch by truncating the
// WAL would destroy it there, and nothing would look wrong: the node still holds
// it in memory and would forward it next time. It only becomes visible if the
// node restarts first, and then the entry is simply gone.
func TestReplayKeepsEventsAppendedDuringTheForward(t *testing.T) {
	cache, wal := newCache(t)
	seed(t, cache, 3)

	// The forward appends a new door event before returning success.
	pol := &appendingPolicy{
		stubPolicy: stubPolicy{},
		cache:      cache,
	}
	svc := NewEdgeServiceWithPolicy(cache, pol, quietLogger())

	if _, err := svc.ReplayEvents(context.Background()); err != nil {
		t.Fatalf("ReplayEvents: %v", err)
	}

	// The event appended mid-forward must still be on disk, not just in memory.
	found := false
	for _, line := range walLines(t, wal) {
		if strings.Contains(line, "evt-during") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the WAL no longer holds the event appended during the forward; "+
			"a restart would lose a door decision that was never forwarded\nWAL: %v", walLines(t, wal))
	}
	if n := cache.GetOfflineEventCount(context.Background()); n != 1 {
		t.Fatalf("queue holds %d events, want the 1 appended mid-forward", n)
	}
}

// appendingPolicy simulates a door scan landing while the batch is in flight.
type appendingPolicy struct {
	stubPolicy
	cache ports.EdgeRepository
}

func (s *appendingPolicy) RecordAccessEvents(
	ctx context.Context, in *accesscontrolv1.RecordAccessEventsRequest, opts ...grpc.CallOption,
) (*accesscontrolv1.RecordAccessEventsResponse, error) {
	resp, err := s.stubPolicy.RecordAccessEvents(ctx, in, opts...)
	if err != nil {
		return resp, err
	}
	if err := s.cache.AppendOfflineEvent(ctx, &domain.OfflineAuditLog{
		EventID:       "evt-during",
		TurnstileID:   "t-1",
		EmployeeID:    "EMP-2",
		ZoneID:        "zone-main-gate",
		AccessGranted: true,
		Decision:      "granted during replay",
		TimestampUnix: 1700009999,
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// TestReplayForwardsEventsUpstream is the baseline: a healthy replay must
// actually send the events somewhere.
//
// Before this, ReplayEvents drained the queue and handed the events to a
// handler that returned only a count, so the audit trail was destroyed by the
// act of replaying it, and the central access_events table was never written by
// any code path.
func TestReplayForwardsEventsUpstream(t *testing.T) {
	cache, wal := newCache(t)
	seed(t, cache, 3)
	pol := &stubPolicy{}
	svc := NewEdgeServiceWithPolicy(cache, pol, quietLogger())

	replayed, err := svc.ReplayEvents(context.Background())
	if err != nil {
		t.Fatalf("ReplayEvents: %v", err)
	}
	if len(replayed) != 3 {
		t.Fatalf("replayed %d events, want 3", len(replayed))
	}
	if len(pol.batches) != 1 || len(pol.batches[0]) != 3 {
		t.Fatalf("upstream received %d batches, want 1 of 3 events", len(pol.batches))
	}
	// The forwarded record must carry what makes it useful in an investigation.
	got := pol.batches[0][0]
	if got.GetEventId() == "" || got.GetEmployeeId() != "EMP-1" || got.GetTurnstileId() != "t-1" {
		t.Fatalf("forwarded event is incomplete: %+v", got)
	}
	if !got.GetAccessGranted() || got.GetOccurredUnix() == 0 {
		t.Fatalf("forwarded event lost its outcome or timestamp: %+v", got)
	}
	// The zone must be the one the edge decided against, not a later lookup:
	// "who entered the main gate" is the question the central log exists to
	// answer, and a dropped zone column makes it unanswerable.
	if got.GetZoneId() != "zone-main-gate" {
		t.Fatalf("forwarded event lost its zone (got %q); the audit table stores an empty zone", got.GetZoneId())
	}
	if !got.GetProcessedOffline() {
		t.Fatalf("forwarded event is not marked as decided offline, so a later audit cannot distinguish a cached decision from a live one: %+v", got)
	}

	// Only now may the durable copy be discarded.
	if lines := walLines(t, wal); len(lines) != 0 {
		t.Fatalf("WAL still holds %d lines after a confirmed replay", len(lines))
	}
	if n := cache.GetOfflineEventCount(context.Background()); n != 0 {
		t.Fatalf("queue holds %d events after a confirmed replay", n)
	}
}

// TestReplayFailureRetainsTheAuditTrail is the property that was missing.
//
// A replay whose upstream forward fails must leave the evidence intact. Before
// this, DrainOfflineEvents truncated the WAL as part of the read, so a failed
// replay destroyed the only copy of who entered which door.
func TestReplayFailureRetainsTheAuditTrail(t *testing.T) {
	cache, wal := newCache(t)
	seed(t, cache, 3)
	pol := &stubPolicy{err: status.Error(codes.Unavailable, "policy unreachable")}
	svc := NewEdgeServiceWithPolicy(cache, pol, quietLogger())

	if _, err := svc.ReplayEvents(context.Background()); err == nil {
		t.Fatal("ReplayEvents reported success while the upstream forward was failing")
	}

	if lines := walLines(t, wal); len(lines) != 3 {
		t.Fatalf("WAL holds %d lines after a failed replay, want 3; the audit trail was destroyed", len(lines))
	}
	if n := cache.GetOfflineEventCount(context.Background()); n != 3 {
		t.Fatalf("queue holds %d events after a failed replay, want 3", n)
	}
}

// TestReplayWithoutUpstreamRetainsEvents covers the deployment where no
// access-policy client is wired: the events must not be dropped either.
func TestReplayWithoutUpstreamRetainsEvents(t *testing.T) {
	cache, wal := newCache(t)
	seed(t, cache, 2)
	svc := NewEdgeService(cache, quietLogger())

	if _, err := svc.ReplayEvents(context.Background()); err == nil {
		t.Fatal("ReplayEvents reported success with no upstream configured")
	}
	if lines := walLines(t, wal); len(lines) != 2 {
		t.Fatalf("WAL holds %d lines, want 2; events were discarded with no upstream", len(lines))
	}
}

// TestReplayRetryAfterFailureSucceeds is the recovery path an operator actually
// exercises: the forward fails, connectivity returns, and the replay is retried.
func TestReplayRetryAfterFailureSucceeds(t *testing.T) {
	cache, wal := newCache(t)
	seed(t, cache, 2)
	pol := &stubPolicy{err: errors.New("temporary outage")}
	svc := NewEdgeServiceWithPolicy(cache, pol, quietLogger())

	if _, err := svc.ReplayEvents(context.Background()); err == nil {
		t.Fatal("expected the first replay to fail")
	}

	pol.err = nil
	if _, err := svc.ReplayEvents(context.Background()); err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if len(pol.batches) == 0 {
		t.Fatal("retry did not forward anything upstream")
	}
	if lines := walLines(t, wal); len(lines) != 0 {
		t.Fatalf("WAL still holds %d lines after a successful retry", len(lines))
	}
}

// TestReplayPartiallyFailsRetainsOnlyUnacknowledgedEvents covers the batching
// path: with one batch succeeding and a later one failing, the acknowledged
// part is already upstream and only the remainder is put back.
func TestReplayPartiallyFailsRetainsOnlyUnacknowledgedEvents(t *testing.T) {
	cache, _ := newCache(t)
	// 250 events with a batch size of 200 forces two batches.
	seedRange(t, cache, 250)

	pol := &countingPolicy{failAfter: 1}
	svc := NewEdgeServiceWithPolicy(cache, pol, quietLogger())

	if _, err := svc.ReplayEvents(context.Background()); err == nil {
		t.Fatal("expected the second batch to fail")
	}
	if pol.calls != 2 {
		t.Fatalf("upstream saw %d batches, want 2", pol.calls)
	}
	// 50 events were never delivered and must still be queued.
	if n := cache.GetOfflineEventCount(context.Background()); n != 50 {
		t.Fatalf("queue holds %d events, want the 50 undelivered ones", n)
	}
}

// TestReplayBatchesLargeBacklog confirms a long outage does not produce one
// RPC per door entry.
func TestReplayBatchesLargeBacklog(t *testing.T) {
	cache, _ := newCache(t)
	seedRange(t, cache, 450)
	pol := &stubPolicy{}
	svc := NewEdgeServiceWithPolicy(cache, pol, quietLogger())

	if _, err := svc.ReplayEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pol.batches) != 3 {
		t.Fatalf("450 events produced %d batches, want 3", len(pol.batches))
	}
}

func seedRange(t *testing.T, c ports.EdgeRepository, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := c.AppendOfflineEvent(context.Background(), &domain.OfflineAuditLog{
			EventID:       "evt-" + itoa(i),
			TurnstileID:   "t-1",
			EmployeeID:    "EMP-1",
			AccessGranted: true,
			TimestampUnix: 1700000000 + int64(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// countingPolicy fails once the configured number of batches have been served.
type countingPolicy struct {
	accesscontrolv1.AccessPolicyServiceClient
	calls     int
	failAfter int
}

func (s *countingPolicy) RecordAccessEvents(
	_ context.Context, in *accesscontrolv1.RecordAccessEventsRequest, _ ...grpc.CallOption,
) (*accesscontrolv1.RecordAccessEventsResponse, error) {
	s.calls++
	if s.calls > s.failAfter {
		return nil, status.Error(codes.Unavailable, "policy unreachable")
	}
	return &accesscontrolv1.RecordAccessEventsResponse{Recorded: uint32(len(in.GetEvents()))}, nil
}
