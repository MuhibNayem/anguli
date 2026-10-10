package ports

import (
	"context"

	"finger-scanner/services/edge-gateway-service/internal/domain"
)

// EdgeRepository defines cache operations and offline journaling for fog nodes.
type EdgeRepository interface {
	UpsertEmployee(ctx context.Context, emp *domain.CachedEmployee) error
	GetEmployee(ctx context.Context, employeeID string) (*domain.CachedEmployee, error)
	ListAllEmployees(ctx context.Context) ([]*domain.CachedEmployee, error)
	AppendOfflineEvent(ctx context.Context, event *domain.OfflineAuditLog) error
	// TakeOfflineEvents removes events from the queue WITHOUT discarding the
	// durable WAL, so a caller can forward them upstream and acknowledge only
	// once that has actually happened.
	//
	// It replaces DrainOfflineEvents, which truncated the WAL as part of the
	// read. That made the durable copy disappear before anything had been
	// stored anywhere else, so a replay that failed - or a replay whose results
	// were discarded - destroyed the only record of who entered which door.
	TakeOfflineEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error)

	// AcknowledgeOfflineEvents discards the durable WAL after the taken events
	// have been confirmed stored upstream. Only then is it safe.
	AcknowledgeOfflineEvents(ctx context.Context) error

	// RestoreOfflineEvents returns previously taken events to the front of the
	// queue, used when forwarding them upstream fails.
	RestoreOfflineEvents(ctx context.Context, events []*domain.OfflineAuditLog) error
	GetOfflineEventCount(ctx context.Context) uint32

	// Policy cache for offline fog node authorization
	UpsertPolicyRule(ctx context.Context, rule *domain.PolicyRule) error
	GetPolicyRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error)

	// Local pass event ledger for offline symmetric anti-passback
	RecordPassEvent(ctx context.Context, event *domain.PassEvent) error
	GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error)
}
