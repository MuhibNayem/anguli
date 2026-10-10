package ports

import (
	"context"

	"finger-scanner/services/access-policy-service/internal/domain"
)

// PolicyRepository defines persistence for access rules and anti-passback state.
type PolicyRepository interface {
	SaveRule(ctx context.Context, rule *domain.PolicyRule) error
	GetRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error)
	GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error)
	RecordPassEvent(ctx context.Context, event *domain.PassEvent) error
	ResetAntiPassback(ctx context.Context, employeeID, zoneID string) error
	GetEmployeeRole(ctx context.Context, employeeID string) (string, error)
	SetEmployeeRole(ctx context.Context, employeeID, role string) error
}
