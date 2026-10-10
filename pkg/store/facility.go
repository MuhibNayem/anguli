package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrFacilityMismatch is returned when a database already belongs to a different
// facility than the one now configured against it.
var ErrFacilityMismatch = errors.New("store: database belongs to a different facility")

// facilitySingleton is the only row key permitted in deployment_identity. A
// singleton table makes "which facility is this" a fact about the database
// rather than a column that could be updated by accident.
const facilitySingleton = 1

// ClaimFacility records which facility this database serves, and refuses to
// start if it was already claimed by another one.
//
// Every other table in this schema is keyed without a facility, which is correct
// for a single-facility deployment and silently wrong for a multi-site one: two
// sites that both name a zone "lobby" share one policy row, so an operator
// tightening one site's lobby threshold quietly changes the other's, with no
// error anywhere.
//
// Scoping the whole schema properly is a large change that must land across
// every table at once - half of it is worse than none of it, because a
// partially scoped schema reads as isolated while still merging sites. So the
// boundary is made explicit and enforced here instead, and this row is the
// anchor a future multi-facility schema can be migrated onto.
//
// Idempotent: claiming the same facility twice succeeds and changes nothing,
// which matters because this runs on every boot.
func (s *Store) ClaimFacility(ctx context.Context, facilityID string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store: ClaimFacility on a nil store")
	}
	facilityID = strings.TrimSpace(facilityID)
	if facilityID == "" {
		// An empty facility would make every claim compare equal to every other,
		// turning the guard into a no-op that appears to be working.
		return fmt.Errorf("store: ClaimFacility requires a non-empty facility id")
	}

	var existing string
	err := s.DB().QueryRowContext(ctx,
		`SELECT facility_id FROM deployment_identity WHERE singleton = ?`, facilitySingleton).Scan(&existing)
	switch {
	case err == sql.ErrNoRows:
		if _, err := s.DB().ExecContext(ctx, s.Rebind(`
INSERT INTO deployment_identity (singleton, facility_id, claimed_at_unix)
VALUES (?, ?, ?)
ON CONFLICT (singleton) DO NOTHING`),
			facilitySingleton, facilityID, NowUnix()); err != nil {
			return fmt.Errorf("store: claim facility %q: %w", facilityID, err)
		}
		// Two services may start against the same database at once. Re-read so
		// the loser of that race is told the truth rather than assuming it won.
		if err := s.DB().QueryRowContext(ctx,
			`SELECT facility_id FROM deployment_identity WHERE singleton = ?`,
			facilitySingleton).Scan(&existing); err != nil {
			return fmt.Errorf("store: read back claimed facility: %w", err)
		}
		if existing != facilityID {
			return facilityMismatchError(existing, facilityID)
		}
		return nil
	case err != nil:
		return fmt.Errorf("store: read facility identity: %w", err)
	}

	if existing != facilityID {
		return facilityMismatchError(existing, facilityID)
	}
	return nil
}

// FacilityID reports the facility this database belongs to, or "" when it has
// not been claimed yet.
func (s *Store) FacilityID(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("store: FacilityID on a nil store")
	}
	var id string
	err := s.DB().QueryRowContext(ctx,
		`SELECT facility_id FROM deployment_identity WHERE singleton = ?`, facilitySingleton).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: read facility identity: %w", err)
	}
	return id, nil
}

func facilityMismatchError(existing, requested string) error {
	return fmt.Errorf("%w: this database holds access policies, templates and "+
		"anti-passback history for facility %q, but it is configured as %q. Every "+
		"table here is keyed without a facility, so pointing one database at two "+
		"facilities merges their zone policies and employee roles silently. Give "+
		"each facility its own STORAGE_DATA_DIR, or set FACILITY_ID back to %q",
		ErrFacilityMismatch, existing, requested, existing)
}
