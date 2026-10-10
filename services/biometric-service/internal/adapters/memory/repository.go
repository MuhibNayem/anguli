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
	// A revoked template reads as absent, so 1:1 verification of an offboarded
	// employee fails the same way it would for someone never enrolled.
	if !exists || tmpl.Revoked {
		return nil, ErrNotFound
	}
	tmplCopy := *tmpl
	return &tmplCopy, nil
}

// ListAll returns only templates that are still live.
//
// Revoked templates are excluded here for the same reason they are excluded in
// sqlstore: this feeds the 1:N gallery, and a revoked template that is still
// returned would keep being matched after someone has been offboarded.
func (r *inMemoryRepository) ListAll(ctx context.Context) ([]*domain.EnrolledTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*domain.EnrolledTemplate, 0, len(r.all))
	for _, t := range r.all {
		if t.Revoked {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// Revoke flags a template out of every read path and archives it for audit,
// mirroring the sqlstore adapter so the two stay behaviourally identical.
func (r *inMemoryRepository) Revoke(
	ctx context.Context, employeeID string, position int32, reason string, atUnix int64,
) (bool, error) {
	if employeeID == "" {
		return false, errors.New("cannot revoke for an empty employee id")
	}
	if reason == "" {
		reason = "UNSPECIFIED"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%d", employeeID, position)
	prior, exists := r.templates[key]
	if !exists || prior.Revoked {
		return false, nil
	}

	r.auditHistory = append(r.auditHistory, &domain.RevocationRecord{
		TemplateID:    prior.TemplateID,
		EmployeeID:    prior.EmployeeID,
		Position:      prior.Position,
		RevokedAtUnix: atUnix,
		Reason:        reason,
		PriorPayload:  prior.EncryptedPayload,
	})

	// Replace rather than mutate in place: callers hold pointers into this map
	// and a revoked template must not change underneath them.
	revokedCopy := *prior
	revokedCopy.Revoked = true
	r.templates[key] = &revokedCopy
	for i, t := range r.all {
		if t.EmployeeID == employeeID && t.Position == position {
			r.all[i] = &revokedCopy
			break
		}
	}
	return true, nil
}
