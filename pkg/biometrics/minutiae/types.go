package minutiae

// MinutiaType defines the structural classification of a minutia point.
type MinutiaType uint8

const (
	TypeUnspecified MinutiaType = 0
	TypeEnding      MinutiaType = 1 // Ridge termination
	TypeBifurcation MinutiaType = 2 // Ridge fork
)

// Minutia represents a single extracted feature point.
type Minutia struct {
	X       uint16      `json:"x"`
	Y       uint16      `json:"y"`
	Angle   float64     `json:"angle"` // Heading angle in radians [0, 2π)
	Type    MinutiaType `json:"type"`
	Quality uint8       `json:"quality"` // Reliability confidence [0, 100]
}

// Template represents the full set of extracted minutiae points for a fingerprint.
type Template struct {
	Width  int       `json:"width"`
	Height int       `json:"height"`
	Points []Minutia `json:"points"`
	NFIQ   uint8     `json:"nfiq"`
}
