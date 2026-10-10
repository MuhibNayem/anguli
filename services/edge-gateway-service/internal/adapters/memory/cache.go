package memory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/ports"
)

var (
	ErrEmployeeNotFoundInCache   = errors.New("employee not found in local edge roster cache")
	ErrPolicyRuleNotFoundInCache = errors.New("policy rule not found in local edge policy cache")
)

type memoryEdgeCache struct {
	mu            sync.RWMutex
	roster        map[string]*domain.CachedEmployee
	offlineEvents []*domain.OfflineAuditLog
	policies      map[string]*domain.PolicyRule
	passEvents    map[string]*domain.PassEvent
	walPath       string
}

// NewMemoryEdgeCache creates a thread-safe local edge cache with durable disk-backed WAL.
//
// The default path matters more than it looks. This file is the audit trail for
// door activity that happened while the fog node could not reach the core -
// the entries that would otherwise vanish without anyone noticing. Two
// defaults are actively wrong for that job:
//
//   - os.TempDir() is a fixed name, so two edge instances on one host opened
//     the same file and interleaved each other's audit records into a single
//     corrupt log.
//   - os.TempDir() is also volatile: a reboot, a tmpfiles sweep or a container
//     recreate silently discarded the offline audit trail.
//
// So the default is now a relative "data" directory, matching the STORAGE_DATA_DIR
// convention the other services use, which resolves under the persistent volume
// a real deployment mounts. EDGE_WAL_PATH overrides it when a specific file is
// wanted; the edge deployment sets it to /data/edge-offline.wal.
func NewMemoryEdgeCache() ports.EdgeRepository {
	walPath := os.Getenv("EDGE_WAL_PATH")
	if walPath == "" {
		dataDir := os.Getenv("EDGE_DATA_DIR")
		if dataDir == "" {
			dataDir = "data"
		}
		walPath = filepath.Join(dataDir, "edge-offline.wal")
	}
	return NewDurableEdgeCache(walPath)
}

// NewDurableEdgeCache creates an edge cache with explicit WAL file path for crash resilience.
func NewDurableEdgeCache(walPath string) ports.EdgeRepository {
	cache := &memoryEdgeCache{
		roster:        make(map[string]*domain.CachedEmployee),
		offlineEvents: make([]*domain.OfflineAuditLog, 0),
		policies: map[string]*domain.PolicyRule{
			"zone-main-gate": {
				ZoneID:                "zone-main-gate",
				AllowedRole:           "EMPLOYEE",
				RequireBiometrics:     true,
				MinBiometricScore:     60.0,
				EnforceAntiPassback:   true,
				AntiPassbackWindowSec: 60,
			},
		},
		passEvents: make(map[string]*domain.PassEvent),
		walPath:    walPath,
	}

	// Recover pending un-replayed offline events from WAL file if present
	cache.recoverWAL()

	return cache
}

func (c *memoryEdgeCache) recoverWAL() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.walPath == "" {
		return
	}

	file, err := os.Open(c.walPath)
	if err != nil {
		return // File does not exist yet
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event domain.OfflineAuditLog
		if err := json.Unmarshal(line, &event); err == nil {
			c.offlineEvents = append(c.offlineEvents, &event)
		}
	}
}

func (c *memoryEdgeCache) UpsertEmployee(ctx context.Context, emp *domain.CachedEmployee) error {
	if emp == nil || emp.EmployeeID == "" {
		return errors.New("cannot cache invalid employee record")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Defensive copy
	empCopy := *emp
	c.roster[emp.EmployeeID] = &empCopy
	return nil
}

func (c *memoryEdgeCache) GetEmployee(ctx context.Context, employeeID string) (*domain.CachedEmployee, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	emp, exists := c.roster[employeeID]
	if !exists {
		return nil, ErrEmployeeNotFoundInCache
	}
	empCopy := *emp
	return &empCopy, nil
}

func (c *memoryEdgeCache) ListAllEmployees(ctx context.Context) ([]*domain.CachedEmployee, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]*domain.CachedEmployee, 0, len(c.roster))
	for _, emp := range c.roster {
		empCopy := *emp
		out = append(out, &empCopy)
	}
	return out, nil
}

func (c *memoryEdgeCache) AppendOfflineEvent(ctx context.Context, event *domain.OfflineAuditLog) error {
	if event == nil {
		return errors.New("cannot append nil offline event")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Bound in-memory queue to prevent memory exhaustion on prolonged offline operation
	if len(c.offlineEvents) > 100000 {
		c.offlineEvents = c.offlineEvents[1:]
	}

	eventCopy := *event
	c.offlineEvents = append(c.offlineEvents, &eventCopy)

	// Persist to durable disk WAL file with synchronous fsync
	if c.walPath != "" {
		_ = os.MkdirAll(filepath.Dir(c.walPath), 0750)
		file, err := os.OpenFile(c.walPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			defer file.Close()
			data, err := json.Marshal(event)
			if err == nil {
				_, _ = file.Write(append(data, '\n'))
				_ = file.Sync()
			}
		}
	}

	return nil
}

func (c *memoryEdgeCache) DrainOfflineEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	drained := c.offlineEvents
	c.offlineEvents = make([]*domain.OfflineAuditLog, 0)

	// Truncate WAL file on disk once events are safely drained upstream
	if c.walPath != "" {
		_ = os.Truncate(c.walPath, 0)
	}

	return drained, nil
}

func (c *memoryEdgeCache) GetOfflineEventCount(ctx context.Context) uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint32(len(c.offlineEvents))
}

func (c *memoryEdgeCache) UpsertPolicyRule(ctx context.Context, rule *domain.PolicyRule) error {
	if rule == nil || rule.ZoneID == "" {
		return errors.New("cannot cache invalid policy rule")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ruleCopy := *rule
	c.policies[rule.ZoneID] = &ruleCopy
	return nil
}

func (c *memoryEdgeCache) GetPolicyRule(ctx context.Context, zoneID string) (*domain.PolicyRule, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rule, exists := c.policies[zoneID]
	if !exists {
		// If requesting unknown zone, fail-safe closed
		return nil, ErrPolicyRuleNotFoundInCache
	}
	ruleCopy := *rule
	return &ruleCopy, nil
}

func (c *memoryEdgeCache) RecordPassEvent(ctx context.Context, event *domain.PassEvent) error {
	if event == nil || event.EmployeeID == "" || event.ZoneID == "" {
		return errors.New("cannot record invalid pass event")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	key := event.EmployeeID + ":" + event.ZoneID
	eventCopy := *event
	c.passEvents[key] = &eventCopy
	return nil
}

func (c *memoryEdgeCache) GetLastPassEvent(ctx context.Context, employeeID, zoneID string) (*domain.PassEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := employeeID + ":" + zoneID
	ev, exists := c.passEvents[key]
	if !exists {
		return nil, nil
	}
	evCopy := *ev
	return &evCopy, nil
}
