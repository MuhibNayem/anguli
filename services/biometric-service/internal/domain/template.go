package domain

import (
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
)

// DecryptedTemplatePayload holds the ephemeral decrypted biometric features in RAM during active verification.
type DecryptedTemplatePayload struct {
	Minutiae  []minutiae.Minutia `json:"minutiae"`
	Cylinders []mcc.Cylinder     `json:"cylinders"`
}

// EnrolledTemplate represents an enterprise encrypted biometric record at rest.
// In compliance with GDPR Art. 9 & BIPA, zero plaintext biometrics are stored at rest.
type EnrolledTemplate struct {
	TemplateID       string
	EmployeeID       string
	FullName         string
	Position         int32
	NFIQScore        uint32
	MinutiaeCount    uint32
	EncryptedPayload []byte
	EnrolledAtUnix   int64
	Version          uint32
	Revoked          bool
}

// RevocationRecord preserves complete audit provenance when templates are superseded or revoked.
type RevocationRecord struct {
	TemplateID    string
	EmployeeID    string
	Position      int32
	RevokedAtUnix int64
	Reason        string
	PriorPayload  []byte
}

