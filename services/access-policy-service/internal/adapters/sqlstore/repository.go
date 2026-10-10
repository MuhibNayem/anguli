// Package sqlstore provides a durable implementation of the access-policy
// service's PolicyRepository port.
//
// It matters for more than durability. Anti-passback is inherently a shared
// state problem: the whole point of the rule is that an employee cannot enter
// twice within the window. With an in-memory repository, two replicas each
// hold their own map, so an ENTRY recorded by the pod serving Turnstile Lane 1
// is invisible to the pod serving Turnstile Lane 2 - and the second swipe walks
// straight through. That is a silent authorisation bypass, not a performance
// trade-off, so this adapter is the correct default rather than an upgrade.
//
// SQLite is the default for single-node deployments. A multi-replica Kubernetes
// deployment must select PostgreSQL: two SQLite files are two independent
// databases and reproduce exactly the bug this package exists to close.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"finger-scanner/pkg/store"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
)

// ErrNotFound is an alias of the shared sentinel so this adapter and the
// in-memory one are indistinguishable to the service.
var ErrNotFound = ports.ErrNotFound

// Repository is a durable PolicyRepository backed by SQL.
type Repository struct {
	st *store.Store
	// locks serialises pass-event critical sections for non-Postgres drivers.
	// See WithPassEventLock for why SQLite needs it and Postgres does not.
	locks *keyedMutex
}

// New builds a Repository over an open, migrated store.
func New(st *store.Store) (*Repository, error) {
	if st == nil {
		return nil, errors.New("sqlstore: nil store")
	}
	return &Repository{st: st, locks: newKeyedMutex()}, nil
}

var _ ports.PolicyRepository = (*Repository)(nil)

// SaveRule upserts the rule for a zone.
func (r *Repository) SaveRule(ctx context.Context, rule *domain.PolicyRule) error {
	if rule == nil || rule.ZoneID == "" {
		return errors.New("cannot save a nil or zoneless policy rule")
	}
	_, err := r.q(ctx).ExecContext(ctx, r.st.Rebind(`
		INSERT INTO policy_rules
			(zone_id, allowed_role, require_biometrics, min_biometric_score,
			 enforce_anti_passback, anti_passback_window_sec, updated_unix)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (zone_id) DO UPDATE SET
			allowed_role              = excluded.allowed_role,
			require_biometrics        = excluded.require_biometrics,
			min_biometric_score       = excluded.min_biometric_score,
			enforce_anti_passback     = excluded.enforce_anti_passback,
			anti_passback_window_sec  = excluded.anti_passback_window_sec,
			updated_unix              = excluded.updated_unix`),
		rule.ZoneID, rule.AllowedRole, rule.RequireBiometrics, rule.MinBiometricScore,
		rule.EnforceAntiPassback, rule.AntiPassbackWindowSec, store.NowUnix())
	if err != nil {
		return fmt.Errorf("sqlstore: save rule for zone %s: %w", rule.ZoneID, err)
	}
	return nil
}

// GetRule returns the rule for a zone, or ErrNotFound.
func (r *Repository) GetRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error) {
	var out domain.PolicyRule
	err := r.q(ctx).QueryRowContext(ctx, r.st.Rebind(`
		SELECT zone_id, allowed_role, require_biometrics, min_biometric_score,
		       enforce_anti_passback, anti_passback_window_sec
		FROM policy_rules WHERE zone_id = ?`), zoneID).
		Scan(&out.ZoneID, &out.AllowedRole, &out.RequireBiometrics,
			&out.MinBiometricScore, &out.EnforceAntiPassback, &out.AntiPassbackWindowSec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no rule for zone %s", ErrNotFound, zoneID)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get rule for zone %s: %w", zoneID, err)
	}
	return &out, nil
}

// RecordPassEvent appends a pass. Appending rather than overwriting is what
// makes the history auditable and lets the anti-passback check see the most
// recent entry even after a reset.
func (r *Repository) RecordPassEvent(ctx context.Context, event *domain.PassEvent) error {
	if event == nil || event.EmployeeID == "" {
		return errors.New("cannot record a nil or employee-less pass event")
	}
	ts := event.Timestamp
	if ts == 0 {
		ts = store.NowUnix()
	}
	_, err := r.q(ctx).ExecContext(ctx, r.st.Rebind(`
		INSERT INTO pass_events (employee_id, zone_id, door_id, direction, occurred_unix)
		VALUES (?, ?, ?, ?, ?)`),
		event.EmployeeID, event.ZoneID, event.DoorID, event.Direction, ts)
	if err != nil {
		return fmt.Errorf("sqlstore: record pass event for %s: %w", event.EmployeeID, err)
	}
	return nil
}

// GetLastPassEvent returns the most recent pass for an employee at a zone.
func (r *Repository) GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error) {
	var out domain.PassEvent
	err := r.q(ctx).QueryRowContext(ctx, r.st.Rebind(`
		SELECT employee_id, zone_id, door_id, direction, occurred_unix
		FROM pass_events
		WHERE employee_id = ? AND zone_id = ?
		ORDER BY occurred_unix DESC, id DESC
		LIMIT 1`), employeeID, zoneID).
		Scan(&out.EmployeeID, &out.ZoneID, &out.DoorID, &out.Direction, &out.Timestamp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no pass events for %s at %s", ErrNotFound, employeeID, zoneID)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: last pass event for %s: %w", employeeID, err)
	}
	return &out, nil
}

// ResetAntiPassback clears the anti-passback state by recording a synthetic
// departure.
//
// It deliberately does not delete history. Deleting the rows would also work
// for the window check, but destroying the audit trail to implement an
// administrative override is the wrong trade in a system whose access log is
// the record of who went where.
func (r *Repository) ResetAntiPassback(ctx context.Context, employeeID, zoneID string) error {
	_, err := r.q(ctx).ExecContext(ctx, r.st.Rebind(`
		INSERT INTO pass_events (employee_id, zone_id, door_id, direction, occurred_unix)
		VALUES (?, ?, '', 2, ?)`), employeeID, zoneID, store.NowUnix())
	if err != nil {
		return fmt.Errorf("sqlstore: reset anti-passback for %s at %s: %w", employeeID, zoneID, err)
	}
	return nil
}

// GetEmployeeRole returns an employee's role, or ErrNotFound.
func (r *Repository) GetEmployeeRole(ctx context.Context, employeeID string) (string, error) {
	var role string
	err := r.q(ctx).QueryRowContext(ctx, r.st.Rebind(
		`SELECT role FROM employee_roles WHERE employee_id = ?`), employeeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: no role for %s", ErrNotFound, employeeID)
	}
	if err != nil {
		return "", fmt.Errorf("sqlstore: get role for %s: %w", employeeID, err)
	}
	return role, nil
}

// SetEmployeeRole upserts an employee's role.
func (r *Repository) SetEmployeeRole(ctx context.Context, employeeID, role string) error {
	if employeeID == "" {
		return errors.New("cannot set a role for an empty employee id")
	}
	_, err := r.q(ctx).ExecContext(ctx, r.st.Rebind(`
		INSERT INTO employee_roles (employee_id, role, updated_unix)
		VALUES (?, ?, ?)
		ON CONFLICT (employee_id) DO UPDATE SET
			role         = excluded.role,
			updated_unix = excluded.updated_unix`),
		employeeID, role, store.NowUnix())
	if err != nil {
		return fmt.Errorf("sqlstore: set role for %s: %w", employeeID, err)
	}
	return nil
}

// RecordAccessEvents durably stores door decisions reported by an edge node.
//
// Idempotent on event_id. ON CONFLICT DO NOTHING is valid on both SQLite and
// PostgreSQL, so one statement serves both drivers; RowsAffected distinguishes a
// newly stored row from one that was already there.
//
// The whole batch runs in one transaction. A replay that fails halfway would
// otherwise leave the edge unable to tell which rows landed, and it would retry
// the entire batch - which the primary key handles - but only if the partial
// write is either complete or absent.
func (r *Repository) RecordAccessEvents(
	ctx context.Context, events []*domain.AccessAuditEvent,
) (int, int, error) {
	if len(events) == 0 {
		return 0, 0, nil
	}

	now := store.NowUnix()
	tx, err := r.st.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("sqlstore: begin access audit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	recorded := 0
	for _, e := range events {
		if e == nil || e.EventID == "" {
			// An event with no id cannot be deduplicated, and a duplicated
			// audit row is worse than a missing one. Skip it and say so.
			continue
		}
		occurred := e.OccurredUnix
		if occurred == 0 {
			occurred = now
		}
		res, err := tx.ExecContext(ctx, r.st.Rebind(`
INSERT INTO access_audit_events
    (event_id, turnstile_id, employee_id, zone_id, decision, access_granted,
     processed_offline, occurred_unix, recorded_at_unix)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (event_id) DO NOTHING`),
			e.EventID, e.TurnstileID, e.EmployeeID, e.ZoneID, e.Decision,
			boolToInt(e.AccessGranted), boolToInt(e.ProcessedOffline),
			occurred, now)
		if err != nil {
			return 0, 0, fmt.Errorf("sqlstore: record access event %s: %w", e.EventID, err)
		}
		if n, err := res.RowsAffected(); err == nil && n > 0 {
			recorded++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("sqlstore: commit access audit: %w", err)
	}
	return recorded, len(events) - recorded, nil
}

// QueryAccessEvents returns a page of the audit trail, newest first.
//
// The row is selected with limit+1 so the caller can tell "there is more" from
// "this is the last page" without a second COUNT query, which on a large trail
// is far more expensive than the page itself.
//
// Filters are built as parameterised fragments rather than interpolated strings.
// The only value ever interpolated is the clamped page size, which is a Go int
// this function produced itself; every caller-supplied string is a bound
// parameter, so an employee id containing a quote cannot reach the SQL.
func (r *Repository) QueryAccessEvents(
	ctx context.Context, filter domain.AccessEventFilter,
) ([]*domain.AccessAuditEvent, int64, string, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = domain.DefaultAuditQueryLimit
	}
	if limit > domain.MaxAuditQueryLimit {
		limit = domain.MaxAuditQueryLimit
	}

	var where []string
	var args []any
	if filter.EmployeeID != "" {
		where = append(where, "employee_id = ?")
		args = append(args, filter.EmployeeID)
	}
	if filter.ZoneID != "" {
		where = append(where, "zone_id = ?")
		args = append(args, filter.ZoneID)
	}
	if filter.TurnstileID != "" {
		where = append(where, "turnstile_id = ?")
		args = append(args, filter.TurnstileID)
	}
	if filter.FromUnix > 0 {
		where = append(where, "occurred_unix >= ?")
		args = append(args, filter.FromUnix)
	}
	if filter.ToUnix > 0 {
		where = append(where, "occurred_unix <= ?")
		args = append(args, filter.ToUnix)
	}
	switch filter.Outcome {
	case domain.OutcomeGranted:
		where = append(where, "access_granted = 1")
	case domain.OutcomeDenied:
		where = append(where, "access_granted = 0")
	}
	// Keyset pagination. Written out rather than as a row-value comparison
	// because SQLite and PostgreSQL both support it but the expanded form is
	// unambiguous across versions.
	if filter.CursorEventID != "" {
		where = append(where, "(occurred_unix < ? OR (occurred_unix = ? AND event_id < ?))")
		args = append(args, filter.CursorUnix, filter.CursorUnix, filter.CursorEventID)
	}

	query := `
SELECT event_id, turnstile_id, employee_id, zone_id, decision, access_granted,
       processed_offline, occurred_unix
FROM access_audit_events`
	if len(where) > 0 {
		query += "\nWHERE " + strings.Join(where, " AND ")
	}
	// Ties on occurred_unix are broken by event_id so the order is total and the
	// cursor never skips or repeats a row. Without the tiebreak two events in
	// the same second could page indefinitely.
	query += "\nORDER BY occurred_unix DESC, event_id DESC\nLIMIT ?"
	args = append(args, limit+1)

	rows, err := r.st.DB().QueryContext(ctx, r.st.Rebind(query), args...)
	if err != nil {
		return nil, 0, "", fmt.Errorf("sqlstore: query access audit: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*domain.AccessAuditEvent, 0, limit+1)
	for rows.Next() {
		var e domain.AccessAuditEvent
		var granted, offline int
		if err := rows.Scan(&e.EventID, &e.TurnstileID, &e.EmployeeID, &e.ZoneID,
			&e.Decision, &granted, &offline, &e.OccurredUnix); err != nil {
			return nil, 0, "", fmt.Errorf("sqlstore: scan access audit: %w", err)
		}
		e.AccessGranted = granted != 0
		e.ProcessedOffline = offline != 0
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, "", fmt.Errorf("sqlstore: read access audit: %w", err)
	}

	var nextUnix int64
	var nextID string
	if len(out) > limit {
		// The extra row is the proof there is another page. Drop it and point
		// the cursor at the last row actually returned.
		last := out[limit-1]
		nextUnix = last.OccurredUnix
		nextID = last.EventID
		out = out[:limit]
	}
	return out, nextUnix, nextID, nil
}

// boolToInt renders a Go bool as the 0/1 an INTEGER column expects.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
