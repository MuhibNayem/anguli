package service_test

import (
	"context"
	"errors"
	"testing"

	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
	"finger-scanner/services/access-policy-service/internal/service"
)

func TestPolicyService_SymmetricAntiPassback(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewMemoryPolicyRepository()
	svc := service.NewPolicyService(repo, nil)

	empID := "EMP-TEST-001"
	zoneID := "zone-main-gate"
	doorID := "door-01"

	// 1. Initial EXIT swipe without prior entry -> MUST be rejected (Fix C3)
	resExit, err := svc.Evaluate(ctx, empID, zoneID, doorID, 2 /* Exit */, true, 80.0)
	if err != nil {
		t.Fatalf("unexpected error on exit: %v", err)
	}
	if resExit.IsGranted {
		t.Errorf("expected exit without prior entry to be rejected, but was granted")
	}
	if resExit.Decision != 3 {
		t.Errorf("expected APB decision 3, got %d", resExit.Decision)
	}

	// 2. Initial ENTRY swipe -> MUST be granted
	resEntry1, err := svc.Evaluate(ctx, empID, zoneID, doorID, 1 /* Entry */, true, 80.0)
	if err != nil {
		t.Fatalf("unexpected error on initial entry: %v", err)
	}
	if !resEntry1.IsGranted {
		t.Errorf("expected initial entry to be granted, reason: %s", resEntry1.Reason)
	}

	// 3. Immediate 2nd ENTRY swipe -> MUST be rejected by APB
	resEntry2, err := svc.Evaluate(ctx, empID, zoneID, doorID, 1 /* Entry */, true, 80.0)
	if err != nil {
		t.Fatalf("unexpected error on 2nd entry: %v", err)
	}
	if resEntry2.IsGranted {
		t.Errorf("expected consecutive entry to be rejected by APB, but was granted")
	}

	// 4. Valid EXIT swipe after entry -> MUST be granted
	resExitValid, err := svc.Evaluate(ctx, empID, zoneID, doorID, 2 /* Exit */, true, 80.0)
	if err != nil {
		t.Fatalf("unexpected error on valid exit: %v", err)
	}
	if !resExitValid.IsGranted {
		t.Errorf("expected valid exit after entry to be granted, reason: %s", resExitValid.Reason)
	}

	// 5. Consecutive EXIT swipe -> MUST be rejected by APB (already exited)
	resExitDup, err := svc.Evaluate(ctx, empID, zoneID, doorID, 2 /* Exit */, true, 80.0)
	if err != nil {
		t.Fatalf("unexpected error on dup exit: %v", err)
	}
	if resExitDup.IsGranted {
		t.Errorf("expected duplicate exit to be rejected by APB, but was granted")
	}

	// 6. Reset APB clears state
	if err := svc.ResetAPB(ctx, empID, zoneID); err != nil {
		t.Fatalf("failed to reset APB: %v", err)
	}
	resEntryAfterReset, err := svc.Evaluate(ctx, empID, zoneID, doorID, 1 /* Entry */, true, 80.0)
	if err != nil || !resEntryAfterReset.IsGranted {
		t.Errorf("expected entry after reset to be granted")
	}
}

func TestPolicyService_RoleClearanceEvaluation(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewMemoryPolicyRepository()
	svc := service.NewPolicyService(repo, nil)

	// zone-datacenter requires SECURITY_ADMIN
	zoneID := "zone-datacenter"
	doorID := "door-dc-01"

	// EMP-001 has role EMPLOYEE -> MUST be denied access (Fix H4)
	resDenied, err := svc.Evaluate(ctx, "EMP-001", zoneID, doorID, 1, true, 85.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resDenied.IsGranted {
		t.Errorf("expected regular employee to be denied from datacenter")
	}
	if resDenied.Decision != 2 {
		t.Errorf("expected decision 2 (invalid zone clearance), got %d", resDenied.Decision)
	}

	// EMP-007 has role SECURITY_ADMIN -> MUST be granted access (Fix H4)
	resGranted, err := svc.Evaluate(ctx, "EMP-007", zoneID, doorID, 1, true, 85.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resGranted.IsGranted {
		t.Errorf("expected SECURITY_ADMIN to be granted access to datacenter, reason: %s", resGranted.Reason)
	}
}

func TestPolicyService_UnconfiguredZoneRejection(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewMemoryPolicyRepository()
	svc := service.NewPolicyService(repo, nil)

	// Access to non-configured zone -> MUST be denied (Fix H9)
	res, err := svc.Evaluate(ctx, "EMP-001", "zone-unknown-typo", "door-01", 1, true, 90.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsGranted {
		t.Errorf("expected unconfigured zone to be denied, but was granted")
	}
	if res.Decision != 2 {
		t.Errorf("expected decision 2 (invalid zone), got %d", res.Decision)
	}
}

type failingRepo struct {
	ports.PolicyRepository
}

func (f *failingRepo) RecordPassEvent(ctx context.Context, event *domain.PassEvent) error {
	return errors.New("simulated database commit failure")
}

func TestPolicyService_FailClosedOnAuditError(t *testing.T) {
	ctx := context.Background()
	baseRepo := memory.NewMemoryPolicyRepository()
	faultyRepo := &failingRepo{PolicyRepository: baseRepo}
	svc := service.NewPolicyService(faultyRepo, nil)

	// If audit commit fails, door MUST NOT open (Fix H11)
	res, err := svc.Evaluate(ctx, "EMP-001", "zone-main-gate", "door-01", 1, true, 80.0)
	if err == nil {
		t.Errorf("expected error when audit commit fails")
	}
	if res != nil && res.IsGranted {
		t.Errorf("door must fail closed on audit error, but was granted")
	}
}

func TestMemoryPolicyRepo_DefensiveCopy(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewMemoryPolicyRepository()

	rule1, err := repo.GetRule(ctx, "zone-main-gate")
	if err != nil {
		t.Fatalf("failed to get rule: %v", err)
	}

	// Mutate returned pointer (Fix M12)
	rule1.MinBiometricScore = 999.0
	rule1.EnforceAntiPassback = false

	// Fetch again from repo
	rule2, err := repo.GetRule(ctx, "zone-main-gate")
	if err != nil {
		t.Fatalf("failed to get rule: %v", err)
	}

	if rule2.MinBiometricScore == 999.0 || !rule2.EnforceAntiPassback {
		t.Errorf("repository was mutated by external pointer change! Defensive copy failed")
	}
}
