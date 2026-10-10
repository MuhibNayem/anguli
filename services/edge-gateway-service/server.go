package edgegatewayservice

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	grpchandler "finger-scanner/services/edge-gateway-service/internal/adapters/grpc"
	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/ports"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// DefaultOfflineReplayInterval is how often a Node flushes its offline audit WAL
// when nothing else has asked it to. Aliased rather than restated so the public
// default and the one the loop actually applies cannot drift apart.
const DefaultOfflineReplayInterval = service.DefaultOfflineReplayInterval

// OfflineEvent is a door decision the edge made while central storage was
// unreachable. It mirrors the durable WAL record, exposed as a plain struct so a
// host can construct one without importing this module's internal packages.
type OfflineEvent struct {
	EventID       string
	TurnstileID   string
	EmployeeID    string
	ZoneID        string
	AccessGranted bool
	Decision      string
	TimestampUnix int64
}

// Node is a running edge: the turnstile service, its durable offline audit WAL,
// and the loop that flushes that WAL to central storage.
//
// It exists because the parts a host needs are otherwise spread across internal
// packages it cannot import. The practical cost was that the offline audit
// pipeline could not be tested end to end from outside the module - every test
// that mattered called ReplayEvents directly and so could not detect that
// nothing in a running process ever did.
type Node struct {
	svc   service.EdgeUseCase
	cache ports.EdgeRepository
}

// NewNode builds an edge whose offline audit WAL lives at walPath. An empty
// walPath falls back to EDGE_WAL_PATH, then EDGE_DATA_DIR, then ./data.
//
// Note that memory.NewMemoryEdgeCache is a misleading name: it builds the
// durable, disk-backed cache, not a volatile one. Durability at the edge is not
// optional, and the name invites someone to "fix" it into a real in-memory cache.
func NewNode(walPath string, policyClient accesscontrolv1.AccessPolicyServiceClient, logger *slog.Logger) *Node {
	if logger == nil {
		logger = slog.Default()
	}
	if walPath == "" {
		walPath = DefaultWALPath()
	}
	cache := memory.NewDurableEdgeCache(walPath)
	return &Node{svc: service.NewEdgeServiceWithPolicy(cache, policyClient, logger), cache: cache}
}

// DefaultWALPath resolves the offline audit WAL location from the environment,
// matching what the daemon does.
func DefaultWALPath() string {
	if p := os.Getenv("EDGE_WAL_PATH"); p != "" {
		return p
	}
	dir := os.Getenv("EDGE_DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	return filepath.Join(dir, "edge-offline.wal")
}

// Mount registers the node's turnstile service onto a gRPC server.
func (n *Node) Mount(s *grpc.Server) {
	edgegatewayv1.RegisterEdgeGatewayServiceServer(s, grpchandler.NewServer(n.svc))
}

// BufferOfflineEvent records a door decision on the durable WAL, exactly as a
// turnstile scan does.
func (n *Node) BufferOfflineEvent(ctx context.Context, e OfflineEvent) error {
	return n.cache.AppendOfflineEvent(ctx, &domain.OfflineAuditLog{
		EventID:       e.EventID,
		TurnstileID:   e.TurnstileID,
		EmployeeID:    e.EmployeeID,
		ZoneID:        e.ZoneID,
		AccessGranted: e.AccessGranted,
		Decision:      e.Decision,
		TimestampUnix: e.TimestampUnix,
	})
}

// PendingOfflineEvents reports how many door decisions are still buffered locally.
func (n *Node) PendingOfflineEvents(ctx context.Context) uint32 {
	return n.cache.GetOfflineEventCount(ctx)
}

// Replay forwards buffered door decisions to central storage now.
func (n *Node) Replay(ctx context.Context) (int, error) {
	events, err := n.svc.ReplayEvents(ctx)
	return len(events), err
}

// RunOfflineReplayLoop flushes the WAL on a timer until ctx is cancelled.
//
// This is the piece that makes the audit trail real. ReplayEvents was correct and
// reachable through an RPC, but nothing in a running edge process invoked it, so
// door decisions buffered during an outage stayed on one machine's disk forever.
func (n *Node) RunOfflineReplayLoop(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	service.RunOfflineReplayLoop(ctx, n.svc, interval, logger)
}

// RegisterService mounts the edge gateway service onto a gRPC server in standalone mode.
func RegisterService(s *grpc.Server, logger *slog.Logger) {
	NewNode("", nil, logger).Mount(s)
}

// RegisterServiceWithPolicy mounts the edge gateway service connected to central access policy.
func RegisterServiceWithPolicy(s *grpc.Server, policyClient accesscontrolv1.AccessPolicyServiceClient, logger *slog.Logger) {
	NewNode("", policyClient, logger).Mount(s)
}
