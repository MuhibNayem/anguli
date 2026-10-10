package domain

import (
	"finger-scanner/pkg/biometrics/mcc"
)

// CachedEmployee holds local facility employee data for offline edge verification.
type CachedEmployee struct {
	EmployeeID     string
	FullName       string
	Role           string
	Position       int32
	Cylinders      []mcc.Cylinder
	IsActive       bool
	EnrolledAtUnix int64
}

// OfflineAuditLog represents an edge-buffered access event when WAN is disconnected.
//
// ZoneID is captured at decision time, not looked up later on replay. A door can
// be moved to a different zone between the scan and the replay, and the audit
// question is always "where was this person when they were admitted", so the
// value has to be the one the edge actually made the decision against. The
// field is JSON-encoded in the durable WAL, so WALs written before this field
// existed still decode - their zone simply reads empty rather than failing.
type OfflineAuditLog struct {
	EventID       string
	TurnstileID   string
	EmployeeID    string
	ZoneID        string
	AccessGranted bool
	Decision      string
	TimestampUnix int64
}

// TurnstileState tracks hardware health, reader status, and statistics.
type TurnstileState struct {
	TurnstileID          string
	ZoneID               string
	IsOnline             bool
	ReaderConnected      bool
	LocalRosterCount     uint32
	OfflinePendingEvents uint32
	StartTimeUnix        int64
}

// PolicyRule defines clearance and anti-passback rules cached locally at the fog node.
type PolicyRule struct {
	ZoneID                string  `json:"zone_id"`
	AllowedRole           string  `json:"allowed_role"`
	RequireBiometrics     bool    `json:"require_biometrics"`
	MinBiometricScore     float64 `json:"min_biometric_score"`
	EnforceAntiPassback   bool    `json:"enforce_anti_passback"`
	AntiPassbackWindowSec uint32  `json:"anti_passback_window_sec"`
}

// PassEvent records local door passage for edge-evaluated symmetric anti-passback.
type PassEvent struct {
	EmployeeID string `json:"employee_id"`
	ZoneID     string `json:"zone_id"`
	DoorID     string `json:"door_id"`
	Direction  int32  `json:"direction"` // 1 = Entry, 2 = Exit
	Timestamp  int64  `json:"timestamp"`
}
