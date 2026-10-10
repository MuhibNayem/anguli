package store

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// DefaultFacilityID is the facility a deployment serves when FACILITY_ID is not
// set.
//
// It is a single value on purpose. Every table in this schema is keyed without
// a facility, so a deployment serves one facility; this names that facility so
// the boundary is recorded and checked rather than merely assumed.
const DefaultFacilityID = "default"

// FacilityIDFromEnv reads the configured facility identity.
//
// Trimming matters: an operator who leaves trailing whitespace in a .env file
// would otherwise get two different identities for the same site, and the second
// one would be refused by ClaimFacility as though it were another facility.
func FacilityIDFromEnv() string {
	id := strings.TrimSpace(os.Getenv("FACILITY_ID"))
	if id == "" {
		return DefaultFacilityID
	}
	return id
}

// ClaimConfiguredFacility claims the database for the facility named by
// FACILITY_ID, logging which one it is.
//
// A mismatch is returned rather than logged-and-continued: continuing would
// merge two facilities' zone policies, employee roles, templates and
// anti-passback history into one set of rules with no other symptom.
func ClaimConfiguredFacility(ctx context.Context, st *Store, logger *slog.Logger) error {
	facility := FacilityIDFromEnv()
	if err := st.ClaimFacility(ctx, facility); err != nil {
		return err
	}
	if logger != nil {
		logger.InfoContext(ctx, "facility identity confirmed",
			slog.String("facility_id", facility))
	}
	return nil
}
