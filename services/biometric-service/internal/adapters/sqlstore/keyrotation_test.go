package sqlstore

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/store"
	"finger-scanner/services/biometric-service/internal/domain"
)

const testHexA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const testHexB = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

func keyFromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newRotationStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "rotate.db")
	st, err := store.Open(context.Background(), store.Config{Driver: store.DriverSQLite, DSN: dsn})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestKeyRotationMigratesStoredTemplates is the end-to-end proof that rotating
// the template encryption key does not require re-enrolling anyone.
//
// Enrol under key 1, rotate to key 2, confirm the old record is still
// readable, migrate it, and confirm it is then on key 2 and still intact.
// Without this, "rotate the key" means "tell every employee to come back".
func TestKeyRotationMigratesStoredTemplates(t *testing.T) {
	ctx := context.Background()
	st := newRotationStore(t)

	gen1, err := crypto.NewVault(keyFromHex(t, testHexA))
	if err != nil {
		t.Fatal(err)
	}
	repo1, err := New(st)
	if err != nil {
		t.Fatal(err)
	}

	const (
		empID   = "EMP-ROTATE-1"
		pos     = int32(1)
		payload = `{"cylinders":[1,2,3,4],"minutiae":[]}`
	)
	ct, err := gen1.EncryptTemplate([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo1.Save(ctx, &domain.EnrolledTemplate{
		TemplateID:       "t1",
		EmployeeID:       empID,
		Position:         pos,
		EncryptedPayload: ct,
	}); err != nil {
		t.Fatal(err)
	}

	// --- rotate ---
	gen2, err := crypto.NewVault(keyFromHex(t, testHexB))
	if err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(1, keyFromHex(t, testHexA)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(1); err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(2, keyFromHex(t, testHexB)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(2); err != nil {
		t.Fatal(err)
	}
	repo2, err := New(st)
	if err != nil {
		t.Fatal(err)
	}

	// The record written under key 1 must still be readable after rotation.
	rec, err := repo2.GetByEmployeeAndPosition(ctx, empID, pos)
	if err != nil {
		t.Fatalf("enrolment lost across a key rotation: %v", err)
	}
	if !gen2.NeedsReEncryption(rec.EncryptedPayload) {
		t.Fatal("record should be flagged for migration")
	}
	plain, err := gen2.DecryptTemplate(rec.EncryptedPayload)
	if err != nil {
		t.Fatalf("record on the old key no longer decrypts: %v", err)
	}
	if string(plain) != payload {
		t.Fatalf("payload changed: %q", plain)
	}

	// Migrate.
	reWrapped, err := gen2.ReEncrypt(rec.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := crypto.KeyIDOf(reWrapped); kid != 2 {
		t.Fatalf("migrated record has key id %d, want 2", kid)
	}
	rec.EncryptedPayload = reWrapped
	if err := repo2.Save(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// Verify through a fresh repository, i.e. what a restarted service sees.
	repo3, err := New(st)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo3.GetByEmployeeAndPosition(ctx, empID, pos)
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := crypto.KeyIDOf(got.EncryptedPayload); kid != 2 {
		t.Fatalf("stored record key id is %d after migration, want 2", kid)
	}
	plain, err = gen2.DecryptTemplate(got.EncryptedPayload)
	if err != nil {
		t.Fatalf("migrated record does not decrypt: %v", err)
	}
	if string(plain) != payload {
		t.Fatalf("payload changed by migration: %q", plain)
	}
	if gen2.NeedsReEncryption(got.EncryptedPayload) {
		t.Error("migrated record must not be flagged again")
	}
}

// TestOldKeyCannotReadRotatedRecords is the property that makes rotation
// meaningful: after migrating, the old key genuinely no longer protects the
// data. A rotation that left the old key working would give a false sense of
// remediation.
func TestOldKeyCannotReadRotatedRecords(t *testing.T) {
	gen1, err := crypto.NewVault(keyFromHex(t, testHexA))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := gen1.EncryptTemplate([]byte("secret template"))
	if err != nil {
		t.Fatal(err)
	}

	gen2, err := crypto.NewVault(keyFromHex(t, testHexB))
	if err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(1, keyFromHex(t, testHexA)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(1); err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(2, keyFromHex(t, testHexB)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(2); err != nil {
		t.Fatal(err)
	}

	reWrapped, err := gen2.ReEncrypt(ct)
	if err != nil {
		t.Fatal(err)
	}

	// A vault holding ONLY the old key - the state the service is in once
	// MASTER_KEY_PREVIOUS has been dropped - must fail.
	oldOnly, err := crypto.NewVault(keyFromHex(t, testHexA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldOnly.DecryptTemplate(reWrapped); err == nil {
		t.Fatal("a vault holding only the old key decrypted a migrated record; " +
			"removing the old key would not actually revoke access")
	}
}

// TestKeyringSurvivesMigrationThroughListAll covers the shape the keyrotate
// command actually walks.
func TestKeyringSurvivesMigrationThroughListAll(t *testing.T) {
	ctx := context.Background()
	st := newRotationStore(t)

	gen1, _ := crypto.NewVault(keyFromHex(t, testHexA))
	repo, _ := New(st)
	for i := 0; i < 5; i++ {
		ct, err := gen1.EncryptTemplate([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Save(ctx, &domain.EnrolledTemplate{
			TemplateID:       "t",
			EmployeeID:       "E",
			Position:         int32(i),
			EncryptedPayload: ct,
		}); err != nil {
			t.Fatal(err)
		}
	}

	gen2, _ := crypto.NewVault(keyFromHex(t, testHexB))
	if err := gen2.AddKey(1, keyFromHex(t, testHexA)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(1); err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(2, keyFromHex(t, testHexB)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(2); err != nil {
		t.Fatal(err)
	}

	all, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("ListAll returned %d templates, want 5", len(all))
	}

	migrated := 0
	for _, tmpl := range all {
		if !gen2.NeedsReEncryption(tmpl.EncryptedPayload) {
			continue
		}
		plain, err := gen2.DecryptTemplate(tmpl.EncryptedPayload)
		if err != nil {
			t.Fatalf("template %d unreadable before migration: %v", tmpl.Position, err)
		}
		newCT, err := gen2.ReEncrypt(tmpl.EncryptedPayload)
		if err != nil {
			t.Fatal(err)
		}
		verify, err := gen2.DecryptTemplate(newCT)
		if err != nil || string(verify) != string(plain) {
			t.Fatalf("template %d failed its post-migration verification", tmpl.Position)
		}
		tmpl.EncryptedPayload = newCT
		if err := repo.Save(ctx, tmpl); err != nil {
			t.Fatal(err)
		}
		migrated++
	}
	if migrated != 5 {
		t.Fatalf("migrated %d of 5 templates", migrated)
	}

	// Nothing left behind.
	after, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tmpl := range after {
		if gen2.NeedsReEncryption(tmpl.EncryptedPayload) {
			t.Fatalf("template %d still on an old key after migration", tmpl.Position)
		}
	}
}
