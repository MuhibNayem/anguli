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
	// RecordAccessEvents durably stores door decisions and returns how many
	// were newly stored and how many were already present.
	//
	// Recording is idempotent on the event id because a partial failure is the
	// normal case for a batched replay: the edge cannot know which rows
	// upstream committed before the connection dropped, so it retries the whole
	// batch and the primary key does the deduplication. Without that, a single
	// interrupted replay would double every door entry it contained, and a
	// duplicated audit trail is worse than a missing one because it destroys
	// trust in the whole log.
	RecordAccessEvents(ctx context.Context, events []*domain.AccessAuditEvent) (recorded int, duplicates int, err error)

	// QueryAccessEvents returns a page of the audit trail, newest first, and the
	// cursor to continue from. An empty next cursor means the result is
	// exhausted.
	//
	// The read path exists because recording alone does not make an audit trail.
	// Data no application can query answers none of the questions an audit trail
	// exists to answer.
	QueryAccessEvents(ctx context.Context, filter domain.AccessEventFilter) (events []*domain.AccessAuditEvent, nextCursorUnix int64, nextCursorEventID string, err error)

	SaveRule(ctx context.Context, rule *domain.PolicyRule) error
	GetRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error)
	GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error)
	RecordPassEvent(ctx context.Context, event *domain.PassEvent) error
	ResetAntiPassback(ctx context.Context, employeeID, zoneID string) error
	GetEmployeeRole(ctx context.Context, employeeID string) (string, error)
	SetEmployeeRole(ctx context.Context, employeeID, role string) error

	// WithPassEventLock runs fn while holding an exclusive lock scoped to one
	// (employee, zone) pair, and commits only if fn returns nil.
	//
	// This exists because anti-passback is a read-modify-write decision and
	// the two halves cannot be separated. Doing GetLastPassEvent and then
	// RecordPassEvent as independent calls lets two turnstiles served by
	// different replicas both observe "no prior entry" in the same instant and
	// both admit the employee - which is precisely the event the rule exists
	// to prevent. Sharing the state across replicas fixes visibility; it does
	// not make the decision exclusive. Only a lock does that.
	//
	// The lock must be exclusive across PROCESSES, not merely across
	// goroutines. A per-process mutex would serialise correctly on a single
	// node and fail open on the multi-replica deployment this change exists to
	// enable, which is the worst possible outcome: the code reads like the
	// race is closed.
	//
	// fn receives a context that routes any repository call it makes through
	// the same transaction as the lock, so the read and the write are one
	// atomic unit rather than two operations bracketed by a lock.
	WithPassEventLock(ctx context.Context, employeeID, zoneID string, fn func(ctx context.Context) error) error
}
