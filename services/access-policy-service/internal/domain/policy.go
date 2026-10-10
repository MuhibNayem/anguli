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
