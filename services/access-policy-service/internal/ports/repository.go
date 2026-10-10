package ports

import (
	"context"
	"errors"

	"finger-scanner/services/access-policy-service/internal/domain"
)

// ErrNotFound is the single sentinel every PolicyRepository implementation
// uses to report "this row does not exist".
//
// It lives in ports rather than in an adapter because the service has to tell
// "no such rule" - a normal outcome that becomes a clean deny - apart from
// "the database is unreachable", which is a real fault. When each adapter
// exported its own sentinel, the service had to import a concrete adapter to
// branch on, so swapping the in-memory repository for the SQL one silently
// turned an unconfigured zone into a hard error.
var ErrNotFound = errors.New("policy: not found")

// PolicyRepository defines persistence for access rules and anti-passback state.
//
// Implementations must return ErrNotFound - never (nil, nil) - when a row is
// absent, so callers can branch on it without importing an adapter.
type PolicyRepository interface {
	SaveRule(ctx context.Context, rule *domain.PolicyRule) error
	GetRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error)
	GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error)
	RecordPassEvent(ctx context.Context, event *domain.PassEvent) error
	ResetAntiPassback(ctx context.Context, employeeID, zoneID string) error
	GetEmployeeRole(ctx context.Context, employeeID string) (string, error)
	SetEmployeeRole(ctx context.Context, employeeID, role string) error
}
