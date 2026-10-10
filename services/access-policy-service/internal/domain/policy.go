package domain

// PolicyRule defines clearance and anti-passback rules for a physical security zone.
type PolicyRule struct {
	ZoneID                string
	AllowedRole           string
	RequireBiometrics     bool
	MinBiometricScore     float64
	EnforceAntiPassback   bool
	AntiPassbackWindowSec uint32
}

// PassEvent logs an entry or exit event for anti-passback evaluation.
type PassEvent struct {
	EmployeeID string
	ZoneID     string
	DoorID     string
	Direction  int32 // 1 = Entry, 2 = Exit
	Timestamp  int64
}

// AccessAuditEvent is one door decision recorded by an edge node.
type AccessAuditEvent struct {
	// EventID is generated at the edge and is the idempotency key. Replaying a
	// batch after a partial failure must not duplicate a door entry.
	EventID          string
	TurnstileID      string
	EmployeeID       string
	ZoneID           string
	Decision         string
	AccessGranted    bool
	ProcessedOffline bool
	OccurredUnix     int64
}

// AccessEventOutcome filters the audit trail by result.
type AccessEventOutcome int

const (
	// OutcomeAny returns grants and denials alike.
	OutcomeAny AccessEventOutcome = iota
	OutcomeGranted
	OutcomeDenied
)

// AccessEventFilter selects a page of the central access audit trail.
//
// Pagination is a keyset cursor rather than an offset. The trail is append-only
// and read newest-first, so an offset shifts whenever a replay lands mid-scan;
// paging by offset would silently skip events and re-show others. A cursor over
// (OccurredUnix, EventID) is stable against concurrent inserts.
type AccessEventFilter struct {
	EmployeeID  string
	ZoneID      string
	TurnstileID string
	// FromUnix and ToUnix bound decision time inclusively. Zero means unbounded.
	FromUnix int64
	ToUnix   int64
	Outcome  AccessEventOutcome

	// Limit is the page size, already clamped to the server maximum.
	Limit int
	// CursorUnix and CursorEventID continue a previous page. Both zero starts
	// from the newest event.
	CursorUnix    int64
	CursorEventID string
}

// DefaultAuditQueryLimit is the page size used when a caller does not ask for
// one.
const DefaultAuditQueryLimit = 100

// MaxAuditQueryLimit bounds a single page. Without a ceiling, a caller can ask
// for every door entry a site has ever recorded and exhaust gateway memory on a
// deployment with years of history.
const MaxAuditQueryLimit = 1000
