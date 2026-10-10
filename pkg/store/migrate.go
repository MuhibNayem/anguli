package store

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaVersion records the applied migration level so upgrades are ordered
// and repeatable rather than best-effort.
const schemaVersion = 1

// migrations are applied in order inside a transaction. Each statement must be
// valid on both SQLite and PostgreSQL; driver-specific type names are
// substituted by the dialect helpers.
func migrations(d Driver, blob, autoInc string) []string {
	return []string{
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at BIGINT NOT NULL
)`),
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS enrolled_templates (
    employee_id       TEXT    NOT NULL,
    position          INTEGER NOT NULL,
    template_id       TEXT    NOT NULL,
    full_name         TEXT    NOT NULL DEFAULT '',
    nfiq_score        INTEGER NOT NULL DEFAULT 0,
    minutiae_count    INTEGER NOT NULL DEFAULT 0,
    encrypted_payload %s      NOT NULL,
    enrolled_at_unix  BIGINT  NOT NULL,
    version           INTEGER NOT NULL DEFAULT 1,
    revoked           BOOLEAN NOT NULL DEFAULT %s,
    PRIMARY KEY (employee_id, position)
)`, blob, boolLiteral(d)),

		fmt.Sprintf(`
CREATE INDEX IF NOT EXISTS idx_templates_employee
    ON enrolled_templates (employee_id)`),

		fmt.Sprintf(`
CREATE INDEX IF NOT EXISTS idx_templates_revoked
    ON enrolled_templates (revoked)`),

		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS revocation_records (
    id               %s,
    template_id      TEXT    NOT NULL,
    employee_id      TEXT    NOT NULL,
    position         INTEGER NOT NULL,
    revoked_at_unix  BIGINT  NOT NULL,
    reason           TEXT    NOT NULL,
    prior_payload    %s      NOT NULL
)`, autoInc, blob),

		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS access_events (
    id             %s,
    employee_id    TEXT    NOT NULL DEFAULT '',
    zone_id        TEXT    NOT NULL DEFAULT '',
    door_id        TEXT    NOT NULL DEFAULT '',
    decision       TEXT    NOT NULL,
    reason         TEXT    NOT NULL DEFAULT '',
    score          REAL    NOT NULL DEFAULT 0,
    occurred_unix  BIGINT  NOT NULL
)`, autoInc),

		fmt.Sprintf(`
CREATE INDEX IF NOT EXISTS idx_access_events_time
    ON access_events (occurred_unix)`),

		// Central audit log for door decisions.
		//
		// access_events above was created for this purpose and then never
		// written by any code path: every turnstile decision was buffered at
		// the edge and destroyed when the buffer was replayed, so there was no
		// central record of who was let through which door.
		//
		// This is a NEW table rather than a widened access_events on purpose.
		// The migration runner executes CREATE TABLE IF NOT EXISTS on every
		// boot, which cannot add a column to a table that already exists, and
		// SQLite has no ADD COLUMN IF NOT EXISTS to fall back on. An existing
		// deployment therefore keeps its old empty access_events and gains
		// this one, which is safe; rewriting the old table's shape would not be.
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS access_audit_events (
    event_id       TEXT    PRIMARY KEY,
    turnstile_id   TEXT    NOT NULL DEFAULT '',
    employee_id    TEXT    NOT NULL DEFAULT '',
    zone_id        TEXT    NOT NULL DEFAULT '',
    decision       TEXT    NOT NULL DEFAULT '',
    access_granted INTEGER NOT NULL DEFAULT 0,
    processed_offline INTEGER NOT NULL DEFAULT 0,
    occurred_unix  BIGINT  NOT NULL,
    recorded_at_unix BIGINT NOT NULL
)`),

		// event_id is PRIMARY KEY above, so this is the index that makes a
		// replayed batch idempotent rather than duplicating every door entry.
		fmt.Sprintf(`
CREATE INDEX IF NOT EXISTS idx_access_audit_time
    ON access_audit_events (occurred_unix)`),

		fmt.Sprintf(`
CREATE INDEX IF NOT EXISTS idx_access_audit_employee
    ON access_audit_events (employee_id, occurred_unix DESC)`),

		// Access-policy state. These exist so anti-passback survives a restart
		// AND is shared between replicas: an in-memory rule set means an
		// employee can be marked "already entered" at one door and "never
		// entered" at the one next to it.
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS policy_rules (
    zone_id                  TEXT    PRIMARY KEY,
    allowed_role             TEXT    NOT NULL DEFAULT '',
    require_biometrics       BOOLEAN NOT NULL DEFAULT %s,
    min_biometric_score      REAL    NOT NULL DEFAULT 0,
    enforce_anti_passback    BOOLEAN NOT NULL DEFAULT %s,
    anti_passback_window_sec INTEGER NOT NULL DEFAULT 60,
    updated_unix             BIGINT  NOT NULL DEFAULT 0
)`, boolLiteral(d), boolLiteral(d)),

		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS employee_roles (
    employee_id  TEXT PRIMARY KEY,
    role         TEXT NOT NULL DEFAULT '',
    updated_unix BIGINT NOT NULL DEFAULT 0
)`),

		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS pass_events (
    id            %s,
    employee_id   TEXT   NOT NULL,
    zone_id       TEXT   NOT NULL,
    door_id       TEXT   NOT NULL DEFAULT '',
    direction     INTEGER NOT NULL DEFAULT 1,
    occurred_unix BIGINT NOT NULL
)`, autoInc),

		// The lookup behind anti-passback is "most recent pass for this employee
		// at this zone". Without this index every scan reads the whole table,
		// which is the worst place for a scan on the door path.
		fmt.Sprintf(`
CREATE INDEX IF NOT EXISTS idx_pass_events_employee_zone_time
    ON pass_events (employee_id, zone_id, occurred_unix DESC)`),
	}
}

// boolLiteral renders a boolean default valid on the target driver.
func boolLiteral(d Driver) string {
	if d == DriverPostgres {
		return "FALSE"
	}
	return "0"
}

// autoIncType renders an auto-incrementing primary key type per driver.
func autoIncType(d Driver) string {
	if d == DriverPostgres {
		return "BIGSERIAL PRIMARY KEY"
	}
	return "INTEGER PRIMARY KEY AUTOINCREMENT"
}

// Migrate applies the schema. It is idempotent, so it is safe on every boot.
func (s *Store) Migrate(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("store: Migrate on a nil store")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range migrations(s.driver, s.BlobType(), autoIncType(s.driver)) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: migrate %s: %w", firstLine(stmt), err)
		}
	}
	// Recording the version must be idempotent: Migrate runs on every boot, and
	// a plain INSERT fails the second time with a unique-constraint violation.
	// ON CONFLICT DO NOTHING is valid on both SQLite and PostgreSQL.
	if _, err := tx.ExecContext(ctx, s.Rebind(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)
		 ON CONFLICT (version) DO NOTHING`),
		schemaVersion, NowUnix()); err != nil {
		return fmt.Errorf("store: record schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration: %w", err)
	}
	return nil
}

// SchemaVersion reports the highest applied migration version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}

// firstLine trims a migration statement to something loggable.
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return trimSpace(s[:i])
		}
	}
	return trimSpace(s)
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
