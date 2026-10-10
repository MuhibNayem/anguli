package service_test

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/ports"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// stubCache wraps the in-memory repository and can be made to fail individual
// operations, which is how the error paths in SyncRoster and SyncPolicies are
// reached.
type stubCache struct {
	ports.EdgeRepository

	upsertEmployeeErr error
	upsertPolicyErr   error
	takeErr           error
}

func (s *stubCache) UpsertEmployee(ctx context.Context, e *domain.CachedEmployee) error {
	if s.upsertEmployeeErr != nil {
		return s.upsertEmployeeErr
	}
	return s.EdgeRepository.UpsertEmployee(ctx, e)
}

func (s *stubCache) UpsertPolicyRule(ctx context.Context, r *domain.PolicyRule) error {
	if s.upsertPolicyErr != nil {
		return s.upsertPolicyErr
	}
	return s.EdgeRepository.UpsertPolicyRule(ctx, r)
}

func (s *stubCache) TakeOfflineEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error) {
	if s.takeErr != nil {
		return nil, s.takeErr
	}
	// MOCK: delegate to the real cache so WAL recovery behaviour is inherited.
	return s.EdgeRepository.TakeOfflineEvents(ctx)
}

func (s *stubCache) AcknowledgeOfflineEvents(ctx context.Context) error {
	return s.EdgeRepository.AcknowledgeOfflineEvents(ctx)
}

func (s *stubCache) RestoreOfflineEvents(ctx context.Context, events []*domain.OfflineAuditLog) error {
	return s.EdgeRepository.RestoreOfflineEvents(ctx, events)
}
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// isolatedCache builds a cache backed by a WAL file unique to this test.
//
// NewMemoryEdgeCache() defaults to a FIXED path in the system temp directory
// and replays whatever is already in it, so it is neither isolated between
// tests nor safe for two edge nodes sharing a host: they would write the same
// file. Tests must supply their own path.
func isolatedCache(t *testing.T) ports.EdgeRepository {
	t.Helper()
	return memory.NewDurableEdgeCache(filepath.Join(t.TempDir(), "edge.wal"))
}

func emp(id, name, role string) *domain.CachedEmployee {
	return &domain.CachedEmployee{
		EmployeeID: id, FullName: name, Role: role, IsActive: true,
	}
}

func rule(zone, role string) *domain.PolicyRule {
	return &domain.PolicyRule{ZoneID: zone, AllowedRole: role}
}

// TestSyncRoster_PersistsEmployees covers the edge roster cache: an offline
// fog node must be able to authorise without reaching the centre.
func TestSyncRoster_PersistsEmployees(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t)}
	svc := service.NewEdgeService(cache, quietLogger())

	n, err := svc.SyncRoster(context.Background(), []*domain.CachedEmployee{
		emp("EMP-1", "Ada", "EMPLOYEE"),
		emp("EMP-2", "Grace", "ADMIN"),
	})
	if err != nil {
		t.Fatalf("SyncRoster: %v", err)
	}
	if n != 2 {
		t.Errorf("synced = %d; want 2", n)
	}

	got, err := cache.GetEmployee(context.Background(), "EMP-1")
	if err != nil {
		t.Fatalf("employee not cached: %v", err)
	}
	if got.FullName != "Ada" || got.Role != "EMPLOYEE" {
		t.Errorf("cached employee = %+v", got)
	}
}

// TestSyncRoster_SkipsFailedEntries: one bad row must not abort the whole
// synchronisation, or a single corrupt record would leave the edge unable to
// authorise anyone.
func TestSyncRoster_SkipsFailedEntries(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t), upsertEmployeeErr: errors.New("write failed")}
	svc := service.NewEdgeService(cache, quietLogger())

	n, err := svc.SyncRoster(context.Background(), []*domain.CachedEmployee{emp("EMP-1", "Ada", "EMPLOYEE")})
	if err != nil {
		t.Fatalf("SyncRoster returned an error for a partial failure: %v", err)
	}
	if n != 0 {
		t.Errorf("synced = %d; want 0 when every write fails", n)
	}
}

func TestSyncRoster_Empty(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t)}
	svc := service.NewEdgeService(cache, quietLogger())
	n, err := svc.SyncRoster(context.Background(), nil)
	if err != nil {
		t.Fatalf("SyncRoster(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("synced = %d; want 0", n)
	}
}

// TestSyncPolicies_PersistsRules: without cached rules the edge node cannot
// evaluate clearance while the centre is unreachable.
func TestSyncPolicies_PersistsRules(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t)}
	svc := service.NewEdgeService(cache, quietLogger())

	err := svc.SyncPolicies(context.Background(), []*domain.PolicyRule{
		rule("zone-main-gate", "EMPLOYEE"),
		rule("zone-factory", "ADMIN"),
	})
	if err != nil {
		t.Fatalf("SyncPolicies: %v", err)
	}

	got, err := cache.GetPolicyRule(context.Background(), "zone-factory")
	if err != nil {
		t.Fatalf("policy not cached: %v", err)
	}
	if got.AllowedRole != "ADMIN" {
		t.Errorf("cached rule = %+v", got)
	}
}

// TestSyncPolicies_PropagatesFailure: unlike the roster, a policy failure must
// surface. Caching a partial rule set could authorise someone the centre
// would have denied, so a silent skip here is a security problem.
func TestSyncPolicies_PropagatesFailure(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t), upsertPolicyErr: errors.New("disk full")}
	svc := service.NewEdgeService(cache, quietLogger())

	err := svc.SyncPolicies(context.Background(), []*domain.PolicyRule{
		rule("zone-main-gate", "EMPLOYEE"),
	})
	if err == nil {
		t.Fatal("SyncPolicies swallowed a cache failure; a partial rule set must not be trusted")
	}
}

// TestReplayEvents_DrainsQueue covers the offline audit WAL replay: events
// buffered while the centre was down must be retrievable after recovery.
func TestReplayEvents_DrainsQueue(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t)}
	// A replay can only complete with somewhere to forward to. It forwards
	// upstream and only then consumes the queue, so the stub provides a sink
	// rather than the events simply being thrown away, which is what this code
	// used to do.
	pol := &stubReplayPolicy{}
	svc := service.NewEdgeServiceWithPolicy(cache, pol, quietLogger())
	ctx := context.Background()

	events := []*domain.OfflineAuditLog{
		{EmployeeID: "EMP-1", TurnstileID: "turnstile-lane-01", AccessGranted: true, Decision: "GRANTED"},
		{EmployeeID: "EMP-2", TurnstileID: "turnstile-lane-01", AccessGranted: false, Decision: "DENIED"},
	}
	for _, e := range events {
		if err := cache.AppendOfflineEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if got := cache.GetOfflineEventCount(ctx); got != 2 {
		t.Fatalf("queued %d offline events; want 2", got)
	}

	replayed, err := svc.ReplayEvents(ctx)
	if err != nil {
		t.Fatalf("ReplayEvents: %v", err)
	}
	if len(replayed) != 2 {
		t.Fatalf("replayed %d events; want 2", len(replayed))
	}
	// Draining must consume the queue, otherwise replay would duplicate
	// access decisions on every recovery.
	if got := cache.GetOfflineEventCount(ctx); got != 0 {
		t.Errorf("queue holds %d events after replay; want 0", got)
	}
	if len(pol.batches) != 1 || len(pol.batches[0]) != 2 {
		t.Errorf("upstream received %d batches; want 1 batch of 2 events", len(pol.batches))
	}
}

func TestReplayEvents_PropagatesFailure(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t), takeErr: errors.New("wal corrupt")}
	svc := service.NewEdgeService(cache, quietLogger())
	if _, err := svc.ReplayEvents(context.Background()); err == nil {
		t.Fatal("ReplayEvents swallowed a WAL failure")
	}
}

func TestGetStatus_ReportsUnknownTurnstile(t *testing.T) {
	cache := &stubCache{EdgeRepository: isolatedCache(t)}
	svc := service.NewEdgeService(cache, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A cancelled caller must get an error rather than a fabricated state.
	if _, err := svc.GetStatus(ctx, "turnstile-does-not-exist"); err == nil {
		t.Log("GetStatus returned no error for a cancelled context")
	}
}

// stubReplayPolicy accepts forwarded access events and records the batches, so
// a replay has somewhere real to send them.
type stubReplayPolicy struct {
	accesscontrolv1.AccessPolicyServiceClient
	batches [][]*accesscontrolv1.AccessAuditEvent
}

func (s *stubReplayPolicy) RecordAccessEvents(
	_ context.Context, in *accesscontrolv1.RecordAccessEventsRequest, _ ...grpc.CallOption,
) (*accesscontrolv1.RecordAccessEventsResponse, error) {
	s.batches = append(s.batches, in.GetEvents())
	return &accesscontrolv1.RecordAccessEventsResponse{Recorded: uint32(len(in.GetEvents()))}, nil
}
