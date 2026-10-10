package memory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
)

var (
	// ErrRuleNotFound is kept as a name callers may still reference; it is
	// now an alias of ports.ErrNotFound so both adapters report absence the
	// same way.
	ErrRuleNotFound = ports.ErrNotFound
)

type memoryPolicyRepo struct {
	mu            sync.RWMutex
	rules         map[string]*domain.PolicyRule
	passEvents    map[string]*domain.PassEvent // key: employeeID:zoneID
	employeeRoles map[string]string            // key: employeeID -> role

	// passLocks serialises the anti-passback check-and-record per
	// employee:zone. See WithPassEventLock.
	passLocksMu sync.Mutex
	passLocks   map[string]*sync.Mutex

	// accessAudit holds recorded door decisions keyed by their event id, which
	// is what makes a replayed batch idempotent.
	accessAudit map[string]domain.AccessAuditEvent
}

// NewMemoryPolicyRepository creates a thread-safe repository with standard enterprise defaults.
func NewMemoryPolicyRepository() ports.PolicyRepository {
	repo := &memoryPolicyRepo{
		rules:         make(map[string]*domain.PolicyRule),
		passEvents:    make(map[string]*domain.PassEvent),
		employeeRoles: make(map[string]string),
		passLocks:     make(map[string]*sync.Mutex),
		accessAudit:   make(map[string]domain.AccessAuditEvent),
	}

	// Seed standard default enterprise security zones
	repo.rules["zone-main-gate"] = &domain.PolicyRule{
		ZoneID:                "zone-main-gate",
		AllowedRole:           "EMPLOYEE",
		RequireBiometrics:     true,
		MinBiometricScore:     60.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	}

	repo.rules["zone-factory-floor"] = &domain.PolicyRule{
		ZoneID:                "zone-factory-floor",
		AllowedRole:           "OPERATOR",
		RequireBiometrics:     true,
		MinBiometricScore:     60.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 120,
	}

	repo.rules["zone-datacenter"] = &domain.PolicyRule{
		ZoneID:                "zone-datacenter",
		AllowedRole:           "SECURITY_ADMIN",
		RequireBiometrics:     true,
		MinBiometricScore:     70.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 300,
	}

	// Seed default clearance roles
	repo.employeeRoles["EMP-007"] = "SECURITY_ADMIN"
	repo.employeeRoles["EMP-ADMIN-001"] = "SECURITY_ADMIN"
	repo.employeeRoles["EMP-ADMIN"] = "SECURITY_ADMIN"
	repo.employeeRoles["EMP-OP-001"] = "OPERATOR"
	repo.employeeRoles["EMP-OPERATOR"] = "OPERATOR"
	repo.employeeRoles["EMP-001"] = "EMPLOYEE"
	repo.employeeRoles["EMP-002"] = "EMPLOYEE"

	return repo
}

func (r *memoryPolicyRepo) SaveRule(ctx context.Context, rule *domain.PolicyRule) error {
	if rule == nil || rule.ZoneID == "" {
		return errors.New("cannot save nil or empty policy rule")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ruleCopy := *rule
	r.rules[rule.ZoneID] = &ruleCopy
	return nil
}

func (r *memoryPolicyRepo) GetRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, exists := r.rules[zoneID]
	if !exists {
		// H9: Return explicit error for unconfigured zone rather than silent permissive fallback
		return nil, ErrRuleNotFound
	}
	// M12: Return defensive copy to prevent external mutation of repository state
	ruleCopy := *rule
	return &ruleCopy, nil
}

func (r *memoryPolicyRepo) GetEmployeeRole(ctx context.Context, employeeID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	role, exists := r.employeeRoles[employeeID]
	if !exists {
		// Default enterprise fallback clearance for active personnel
		return "EMPLOYEE", nil
	}
	return role, nil
}

func (r *memoryPolicyRepo) SetEmployeeRole(ctx context.Context, employeeID, role string) error {
	if employeeID == "" {
		return errors.New("employee ID is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.employeeRoles[employeeID] = role
	return nil
}

func (r *memoryPolicyRepo) GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", employeeID, zoneID)
	event, exists := r.passEvents[key]
	if !exists {
		// Not (nil, nil): "no previous pass" is a normal state, and the
		// service must be able to tell it apart from a storage fault.
		return nil, ports.ErrNotFound
	}
	return event, nil
}

// RecordAccessEvents stores door decisions in memory, deduplicating on event id
// exactly as the durable adapter does, so behaviour does not depend on which
// backend a deployment selected.
func (r *memoryPolicyRepo) RecordAccessEvents(
	ctx context.Context, events []*domain.AccessAuditEvent,
) (int, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	recorded, skipped := 0, 0
	for _, e := range events {
		if e == nil || e.EventID == "" {
			skipped++
			continue
		}
		if _, seen := r.accessAudit[e.EventID]; seen {
			skipped++
			continue
		}
		cp := *e
		if r.accessAudit == nil {
			r.accessAudit = make(map[string]domain.AccessAuditEvent)
		}
		r.accessAudit[e.EventID] = cp
		recorded++
	}
	return recorded, skipped, nil
}

// QueryAccessEvents returns a page of the audit trail newest-first, mirroring the
// durable adapter's filters, ordering and cursor exactly.
//
// The shared ordering test in the service package runs against both adapters. A
// test stub that quietly disagreed with the real one is how a security test ends
// up passing for the wrong reason.
func (r *memoryPolicyRepo) QueryAccessEvents(
	_ context.Context, filter domain.AccessEventFilter,
) ([]*domain.AccessAuditEvent, int64, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = domain.DefaultAuditQueryLimit
	}
	if limit > domain.MaxAuditQueryLimit {
		limit = domain.MaxAuditQueryLimit
	}

	matched := make([]*domain.AccessAuditEvent, 0, len(r.accessAudit))
	for _, e := range r.accessAudit {
		if filter.EmployeeID != "" && e.EmployeeID != filter.EmployeeID {
			continue
		}
		if filter.ZoneID != "" && e.ZoneID != filter.ZoneID {
			continue
		}
		if filter.TurnstileID != "" && e.TurnstileID != filter.TurnstileID {
			continue
		}
		if filter.FromUnix > 0 && e.OccurredUnix < filter.FromUnix {
			continue
		}
		if filter.ToUnix > 0 && e.OccurredUnix > filter.ToUnix {
			continue
		}
		switch filter.Outcome {
		case domain.OutcomeGranted:
			if !e.AccessGranted {
				continue
			}
		case domain.OutcomeDenied:
			if e.AccessGranted {
				continue
			}
		}
		if filter.CursorEventID != "" {
			afterCursor := e.OccurredUnix < filter.CursorUnix ||
				(e.OccurredUnix == filter.CursorUnix && e.EventID < filter.CursorEventID)
			if !afterCursor {
				continue
			}
		}
		cp := e
		matched = append(matched, &cp)
	}

	// Total order, newest first, with event id breaking ties on the timestamp so
	// the cursor cannot skip or repeat a row.
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].OccurredUnix != matched[j].OccurredUnix {
			return matched[i].OccurredUnix > matched[j].OccurredUnix
		}
		return matched[i].EventID > matched[j].EventID
	})

	var nextUnix int64
	var nextID string
	if len(matched) > limit {
		last := matched[limit-1]
		nextUnix = last.OccurredUnix
		nextID = last.EventID
		matched = matched[:limit]
	}
	return matched, nextUnix, nextID, nil
}

func (r *memoryPolicyRepo) RecordPassEvent(ctx context.Context, event *domain.PassEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.EmployeeID, event.ZoneID)
	r.passEvents[key] = event
	return nil
}

func (r *memoryPolicyRepo) ResetAntiPassback(ctx context.Context, employeeID, zoneID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", employeeID, zoneID)
	delete(r.passEvents, key)
	return nil
}

// WithPassEventLock serialises the anti-passback check-and-record for one
// employee:zone pair.
//
// This adapter is process-local by nature, so the mutex gives the same
// guarantee the SQL adapter gets from a database advisory lock - for as long
// as the state itself is process-local. It stops being sufficient the moment
// two replicas each hold their own map, which is why the service defaults to
// the SQL adapter and why the Helm chart refuses a multi-replica SQLite
// deployment.
//
// fn returning an error releases the lock without side effects, which here is
// automatic: unlike the SQL adapter there is no transaction to roll back.
func (r *memoryPolicyRepo) WithPassEventLock(ctx context.Context, employeeID, zoneID string, fn func(context.Context) error) error {
	if employeeID == "" || zoneID == "" {
		return errors.New("memory: pass-event lock requires a non-empty employee and zone")
	}

	key := fmt.Sprintf("%s:%s", employeeID, zoneID)

	r.passLocksMu.Lock()
	mu, ok := r.passLocks[key]
	if !ok {
		mu = &sync.Mutex{}
		r.passLocks[key] = mu
	}
	r.passLocksMu.Unlock()

	mu.Lock()
	defer mu.Unlock()

	return fn(ctx)
}
