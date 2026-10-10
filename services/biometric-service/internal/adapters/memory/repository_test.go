package memory_test

import (
	"context"
	"testing"
	"time"

	"finger-scanner/services/biometric-service/internal/adapters/memory"
	"finger-scanner/services/biometric-service/internal/domain"
)

func TestBiometricRepository_ReenrollmentRevocationAudit(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewInMemoryRepository()

	empID := "EMP-TEST-AUDIT"
	pos := int32(1)

	// 1. Initial enrollment (Version 1)
	tmpl1 := &domain.EnrolledTemplate{
		TemplateID:       "tmpl-001",
		EmployeeID:       empID,
		Position:         pos,
		EncryptedPayload: []byte("ciphertext-v1"),
		EnrolledAtUnix:   time.Now().Unix(),
	}
	if err := repo.Save(ctx, tmpl1); err != nil {
		t.Fatalf("failed to save initial template: %v", err)
	}

	fetched1, err := repo.GetByEmployeeAndPosition(ctx, empID, pos)
	if err != nil {
		t.Fatalf("failed to get template: %v", err)
	}
	if fetched1.Version != 1 {
		t.Errorf("expected version 1 on initial save, got %d", fetched1.Version)
	}

	// 2. Re-enrollment with new template (Version 2) -> Must archive old version (Fix M11)
	tmpl2 := &domain.EnrolledTemplate{
		TemplateID:       "tmpl-002",
		EmployeeID:       empID,
		Position:         pos,
		EncryptedPayload: []byte("ciphertext-v2"),
		EnrolledAtUnix:   time.Now().Unix() + 10,
	}
	if err := repo.Save(ctx, tmpl2); err != nil {
		t.Fatalf("failed to save re-enrollment template: %v", err)
	}

	fetched2, err := repo.GetByEmployeeAndPosition(ctx, empID, pos)
	if err != nil {
		t.Fatalf("failed to get updated template: %v", err)
	}
	if fetched2.Version != 2 {
		t.Errorf("expected version 2 after re-enrollment, got %d", fetched2.Version)
	}
	if string(fetched2.EncryptedPayload) != "ciphertext-v2" {
		t.Errorf("expected ciphertext-v2, got %s", string(fetched2.EncryptedPayload))
	}

	// 3. Defensive copy check
	fetched2.FullName = "Mutated In Memory"
	fetched3, _ := repo.GetByEmployeeAndPosition(ctx, empID, pos)
	if fetched3.FullName == "Mutated In Memory" {
		t.Errorf("repository in-memory pointer was mutated! Defensive copy failed")
	}
}
