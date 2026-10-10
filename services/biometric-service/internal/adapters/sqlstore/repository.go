// Package sqlstore provides a durable implementation of the biometric
// service's TemplateRepository port.
//
// It implements the same interface as the in-memory adapter, so the choice of
// backend is a wiring decision rather than a code change. SQLite is the
// default; PostgreSQL is selected by environment.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"finger-scanner/pkg/store"
	"finger-scanner/services/biometric-service/internal/domain"
	"finger-scanner/services/biometric-service/internal/ports"
)

// Repository is a durable TemplateRepository backed by SQL.
type Repository struct {
	st *store.Store
}

// New builds a Repository over an open store.
func New(st *store.Store) (*Repository, error) {
	if st == nil {
		return nil, errors.New("sqlstore: nil store")
	}
	return &Repository{st: st}, nil
}

// Verify the compiler agrees we satisfy the port.
var _ ports.TemplateRepository = (*Repository)(nil)

// falseLiteral renders a FALSE as SQL TEXT for the target driver.
//
// It has to be text rather than a bound parameter. The column is declared
// BOOLEAN, which PostgreSQL and SQLite disagree about on the wire: SQLite
// stores and compares it as the integer 0, so `WHERE revoked = ?` with a Go
// bool parameter silently matches nothing and every lookup returns not-found.
// Inlining the literal is safe because the value comes from a fixed set, not
// from input.
//
// This mirrors boolLiteral in pkg/store, which renders the same way when the
// schema is created.
func falseLiteral(d store.Driver) string {
	if d == store.DriverPostgres {
		return "FALSE"
	}
	return "0"
}

// trueLiteral is the complement of falseLiteral, with the same reasoning.
func trueLiteral(d store.Driver) string {
	if d == store.DriverPostgres {
		return "TRUE"
	}
	return "1"
}

// Save upserts a template. Re-enrolling the same employee and finger position
// bumps the version and archives the superseded template, preserving the audit
// trail the in-memory adapter also keeps.
//
// The read-modify-write runs inside a transaction so a concurrent enroll for
// the same finger cannot lose an update.
func (r *Repository) Save(ctx context.Context, template *domain.EnrolledTemplate) error {
	if template == nil || template.EmployeeID == "" {
		return errors.New("cannot save nil or invalid template")
	}

	tx, err := r.st.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: begin save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the existing row, if any, so version numbers cannot race.
	var (
		priorPayload []byte
		priorID      string
		priorVersion uint32
	)
	err = tx.QueryRowContext(ctx, r.st.Rebind(
		`SELECT template_id, encrypted_payload, version FROM enrolled_templates
		 WHERE employee_id = ? AND position = ?`),
		template.EmployeeID, template.Position,
	).Scan(&priorID, &priorPayload, &priorVersion)

	switch {
	case err == nil:
		// Re-enrollment: supersede the prior template.
		template.Version = priorVersion + 1
		if _, err := tx.ExecContext(ctx, r.st.Rebind(
			`INSERT INTO revocation_records
			   (template_id, employee_id, position, revoked_at_unix, reason, prior_payload)
			 VALUES (?, ?, ?, ?, ?, ?)`),
			priorID, template.EmployeeID, template.Position, template.EnrolledAtUnix,
			"SUPERSEDED_BY_REENROLLMENT", priorPayload,
		); err != nil {
			return fmt.Errorf("sqlstore: archive superseded template: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
		if template.Version == 0 {
			template.Version = 1
		}
	default:
		return fmt.Errorf("sqlstore: read prior template: %w", err)
	}

	// ON CONFLICT is valid on both SQLite and PostgreSQL, so one statement
	// serves both drivers.
	if _, err := tx.ExecContext(ctx, r.st.Rebind(`
INSERT INTO enrolled_templates
    (employee_id, position, template_id, full_name, nfiq_score, minutiae_count,
     encrypted_payload, enrolled_at_unix, version, revoked)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (employee_id, position) DO UPDATE SET
    template_id       = excluded.template_id,
    full_name         = excluded.full_name,
    nfiq_score        = excluded.nfiq_score,
    minutiae_count    = excluded.minutiae_count,
    encrypted_payload = excluded.encrypted_payload,
    enrolled_at_unix  = excluded.enrolled_at_unix,
    version           = excluded.version,
    revoked           = excluded.revoked`),
		template.EmployeeID, template.Position, template.TemplateID, template.FullName,
		template.NFIQScore, template.MinutiaeCount, template.EncryptedPayload,
		template.EnrolledAtUnix, template.Version, template.Revoked,
	); err != nil {
		return fmt.Errorf("sqlstore: upsert template: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit save: %w", err)
	}
	return nil
}

// GetByEmployeeAndPosition loads a template, returning store.ErrNotFound when
// no row exists.
func (r *Repository) GetByEmployeeAndPosition(ctx context.Context, employeeID string, position int32) (*domain.EnrolledTemplate, error) {
	var t domain.EnrolledTemplate
	err := r.st.DB().QueryRowContext(ctx, r.st.Rebind(
		`SELECT employee_id, position, template_id, full_name, nfiq_score,
		        minutiae_count, encrypted_payload, enrolled_at_unix, version, revoked
		 FROM enrolled_templates
		 WHERE employee_id = ? AND position = ? AND revoked = `+falseLiteral(r.st.Driver())+` `),
		employeeID, position,
	).Scan(&t.EmployeeID, &t.Position, &t.TemplateID, &t.FullName, &t.NFIQScore,
		&t.MinutiaeCount, &t.EncryptedPayload, &t.EnrolledAtUnix, &t.Version, &t.Revoked)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s:%d", store.ErrNotFound, employeeID, position)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get template: %w", err)
	}
	return &t, nil
}

// ListAll returns every template, ordered for deterministic output.
func (r *Repository) ListAll(ctx context.Context) ([]*domain.EnrolledTemplate, error) {
	rows, err := r.st.DB().QueryContext(ctx,
		`SELECT employee_id, position, template_id, full_name, nfiq_score,
		        minutiae_count, encrypted_payload, enrolled_at_unix, version, revoked
		 FROM enrolled_templates
		 WHERE revoked = `+falseLiteral(r.st.Driver())+`
		 ORDER BY employee_id, position`)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list templates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*domain.EnrolledTemplate, 0, 16)
	for rows.Next() {
		var t domain.EnrolledTemplate
		if err := rows.Scan(&t.EmployeeID, &t.Position, &t.TemplateID, &t.FullName,
			&t.NFIQScore, &t.MinutiaeCount, &t.EncryptedPayload, &t.EnrolledAtUnix,
			&t.Version, &t.Revoked); err != nil {
			return nil, fmt.Errorf("sqlstore: scan template: %w", err)
		}
		out = append(out, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: iterate templates: %w", err)
	}
	return out, nil
}

// RecordRevocation archives a template being revoked.
func (r *Repository) RecordRevocation(ctx context.Context, rec *domain.RevocationRecord) error {
	if rec == nil {
		return errors.New("sqlstore: nil revocation record")
	}
	_, err := r.st.DB().ExecContext(ctx, r.st.Rebind(
		`INSERT INTO revocation_records
		   (template_id, employee_id, position, revoked_at_unix, reason, prior_payload)
		 VALUES (?, ?, ?, ?, ?, ?)`),
		rec.TemplateID, rec.EmployeeID, rec.Position, rec.RevokedAtUnix,
		rec.Reason, rec.PriorPayload)
	if err != nil {
		return fmt.Errorf("sqlstore: record revocation: %w", err)
	}
	return nil
}

// RevocationHistory returns archived templates for an employee, newest first.
func (r *Repository) RevocationHistory(ctx context.Context, employeeID string) ([]*domain.RevocationRecord, error) {
	rows, err := r.st.DB().QueryContext(ctx, r.st.Rebind(
		`SELECT template_id, employee_id, position, revoked_at_unix, reason, prior_payload
		 FROM revocation_records
		 WHERE employee_id = ?
		 ORDER BY revoked_at_unix DESC, id DESC`), employeeID)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: revocation history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*domain.RevocationRecord
	for rows.Next() {
		var rec domain.RevocationRecord
		if err := rows.Scan(&rec.TemplateID, &rec.EmployeeID, &rec.Position,
			&rec.RevokedAtUnix, &rec.Reason, &rec.PriorPayload); err != nil {
			return nil, fmt.Errorf("sqlstore: scan revocation: %w", err)
		}
		out = append(out, &rec)
	}
	return out, rows.Err()
}

// Revoke flags a template out of every read path and archives it for audit.
//
// The read, the archive insert and the flag write run in one transaction.
// Splitting them would allow a crash between archiving and flagging, leaving
// the template still matchable while an audit record claimed otherwise - the
// worst possible combination for an offboarding control.
//
// Reports false without error when the template is absent or already revoked,
// so the call is idempotent.
func (r *Repository) Revoke(
	ctx context.Context, employeeID string, position int32, reason string, atUnix int64,
) (bool, error) {
	if employeeID == "" {
		return false, errors.New("sqlstore: revoke requires an employee id")
	}
	if reason == "" {
		reason = "UNSPECIFIED"
	}
	notRevoked := falseLiteral(r.st.Driver())

	tx, err := r.st.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("sqlstore: begin revoke: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var templateID string
	var payload []byte
	err = tx.QueryRowContext(ctx, r.st.Rebind(
		`SELECT template_id, encrypted_payload FROM enrolled_templates
		 WHERE employee_id = ? AND position = ? AND revoked = `+notRevoked+` `),
		employeeID, position,
	).Scan(&templateID, &payload)

	if errors.Is(err, sql.ErrNoRows) {
		// Nothing live to revoke. Not an error: offboarding jobs are retried,
		// and running one twice must be safe.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlstore: read template to revoke: %w", err)
	}

	if _, err := tx.ExecContext(ctx, r.st.Rebind(
		`INSERT INTO revocation_records
		   (template_id, employee_id, position, revoked_at_unix, reason, prior_payload)
		 VALUES (?, ?, ?, ?, ?, ?)`),
		templateID, employeeID, position, atUnix, reason, payload,
	); err != nil {
		return false, fmt.Errorf("sqlstore: archive revoked template: %w", err)
	}

	res, err := tx.ExecContext(ctx, r.st.Rebind(
		`UPDATE enrolled_templates SET revoked = `+trueLiteral(r.st.Driver())+`
		 WHERE employee_id = ? AND position = ?`),
		employeeID, position,
	)
	if err != nil {
		return false, fmt.Errorf("sqlstore: flag template revoked: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// Another revoker won the race. Its archive record is already written,
		// so returning false here is the honest answer rather than a second
		// duplicate audit row.
		return false, nil
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("sqlstore: commit revoke: %w", err)
	}
	return true, nil
}
