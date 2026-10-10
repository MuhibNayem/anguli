package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"finger-scanner/services/biometric-service/internal/domain"
	"finger-scanner/services/biometric-service/internal/ports"
)

var (
	ErrNotFound = errors.New("template not found")
)

type inMemoryRepository struct {
	mu           sync.RWMutex
	templates    map[string]*domain.EnrolledTemplate // key: employeeID:position
	all          []*domain.EnrolledTemplate
	auditHistory []*domain.RevocationRecord
}

// NewInMemoryRepository creates a thread-safe in-memory template repository.
func NewInMemoryRepository() ports.TemplateRepository {
	return &inMemoryRepository{
		templates:    make(map[string]*domain.EnrolledTemplate),
		all:          make([]*domain.EnrolledTemplate, 0),
		auditHistory: make([]*domain.RevocationRecord, 0),
	}
}

func (r *inMemoryRepository) Save(ctx context.Context, template *domain.EnrolledTemplate) error {
	if template == nil || template.EmployeeID == "" {
		return errors.New("cannot save nil or invalid template")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%d", template.EmployeeID, template.Position)

	// M11: If re-enrolling, archive superseded template into audit history
	if prior, exists := r.templates[key]; exists {
		template.Version = prior.Version + 1
		r.auditHistory = append(r.auditHistory, &domain.RevocationRecord{
			TemplateID:    prior.TemplateID,
			EmployeeID:    prior.EmployeeID,
			Position:      prior.Position,
			RevokedAtUnix: template.EnrolledAtUnix,
			Reason:        "SUPERSEDED_BY_REENROLLMENT",
			PriorPayload:  prior.EncryptedPayload,
		})
	} else if template.Version == 0 {
		template.Version = 1
	}

	tmplCopy := *template
	r.templates[key] = &tmplCopy

	// Update list slice
	found := false
	for i, t := range r.all {
		if t.EmployeeID == template.EmployeeID && t.Position == template.Position {
			r.all[i] = &tmplCopy
			found = true
			break
		}
	}
	if !found {
		r.all = append(r.all, &tmplCopy)
	}

	return nil
}

func (r *inMemoryRepository) GetByEmployeeAndPosition(ctx context.Context, employeeID string, position int32) (*domain.EnrolledTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", employeeID, position)
	tmpl, exists := r.templates[key]
	if !exists {
		return nil, ErrNotFound
	}
	tmplCopy := *tmpl
	return &tmplCopy, nil
}

func (r *inMemoryRepository) ListAll(ctx context.Context) ([]*domain.EnrolledTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*domain.EnrolledTemplate, len(r.all))
	copy(out, r.all)
	return out, nil
}
