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
}
