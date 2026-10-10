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
	DrainOfflineEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error)
	GetOfflineEventCount(ctx context.Context) uint32

	// Policy cache for offline fog node authorization
	UpsertPolicyRule(ctx context.Context, rule *domain.PolicyRule) error
	GetPolicyRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error)

	// Local pass event ledger for offline symmetric anti-passback
	RecordPassEvent(ctx context.Context, event *domain.PassEvent) error
	GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error)
}
