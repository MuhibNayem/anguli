package ports

import (
	"context"

	"finger-scanner/services/biometric-service/internal/domain"
)

// TemplateRepository defines persistence operations for enrolled biometric templates.
type TemplateRepository interface {
	Save(ctx context.Context, template *domain.EnrolledTemplate) error
	GetByEmployeeAndPosition(ctx context.Context, employeeID string, position int32) (*domain.EnrolledTemplate, error)
	ListAll(ctx context.Context) ([]*domain.EnrolledTemplate, error)

	// Revoke makes a template unusable for matching and archives it for audit.
	//
	// Revocation is deliberately not a delete. The encrypted payload is
	// retained in revocation_records so that "who was enrolled here, and when
	// did that stop being true" stays answerable after someone leaves; the row
	// in enrolled_templates keeps the ciphertext but is flagged out of every
	// read path, so it can never be matched again.
	//
	// Reports whether a live template was actually revoked. Revoking an
	// already-revoked or unknown template is not an error and returns false,
	// which makes the operation idempotent and safe to retry - an offboarding
	// job that is run twice must not fail, and a partial failure must be
	// retryable without special-casing.
	Revoke(ctx context.Context, employeeID string, position int32, reason string, atUnix int64) (bool, error)
}
