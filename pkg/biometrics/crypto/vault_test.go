package crypto_test

import (
	"bytes"
	"testing"

	"finger-scanner/pkg/biometrics/crypto"
)

func TestVaultEncryptionAndDecryption(t *testing.T) {
	key := []byte("01234567890123456789012345678901") // 32 bytes AES-256
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	payload := []byte("biometric-template-confidential-fingerprint-payload")
	ciphertext, err := vault.EncryptTemplate(payload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(ciphertext, payload) {
		t.Errorf("ciphertext should not match plaintext")
	}

	decrypted, err := vault.DecryptTemplate(ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("expected decrypted text to match original payload")
	}

	// Test tamper detection
	ciphertext[len(ciphertext)-1] ^= 0xFF
	_, err = vault.DecryptTemplate(ciphertext)
	if err == nil {
		t.Errorf("expected error on tampered ciphertext, but got nil")
	}
}

func TestCancelableSaltProjection(t *testing.T) {
	x, y := uint16(120), uint16(240)
	angle := 1.25
	saltA := "tenant-facility-alpha-2026"
	saltB := "tenant-facility-beta-2026"

	txA1, tyA1, tAngleA1 := crypto.TransformCancelable(x, y, angle, saltA)
	txA2, tyA2, tAngleA2 := crypto.TransformCancelable(x, y, angle, saltA)
	txB, tyB, tAngleB := crypto.TransformCancelable(x, y, angle, saltB)

	// Repeatability with identical salt
	if txA1 != txA2 || tyA1 != tyA2 || tAngleA1 != tAngleA2 {
		t.Errorf("identical salt must produce deterministic repeatable projection")
	}

	// Unlinkability with different salts
	if txA1 == txB && tyA1 == tyB && tAngleA1 == tAngleB {
		t.Errorf("different salts must produce different projections (unlinkability)")
	}

	// Valid bounds
	if txA1 >= 500 || tyA1 >= 500 || tAngleA1 < 0 || tAngleA1 >= 2*3.141592653589793*1.01 {
		t.Errorf("transformed coordinates out of bounds: (%d, %d, %f)", txA1, tyA1, tAngleA1)
	}
}

func TestVaultKeyRotation(t *testing.T) {
	key1 := []byte("01234567890123456789012345678901") // Key v1
	key2 := []byte("abcdefabcdefabcdefabcdefabcdefab") // Key v2

	vault, err := crypto.NewVault(key1)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	payload := []byte("top-secret-biometric-minutiae-record")

	// Encrypt under Key v1
	ct1, err := vault.EncryptTemplate(payload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Rotate key: Add Key v2 and make it primary
	if err := vault.AddKey(2, key2); err != nil {
		t.Fatalf("failed to add key v2: %v", err)
	}
	if err := vault.RotatePrimaryKey(2); err != nil {
		t.Fatalf("failed to rotate primary key: %v", err)
	}

	// Encrypt new record under Key v2
	ct2, err := vault.EncryptTemplate(payload)
	if err != nil {
		t.Fatalf("encryption under key2 failed: %v", err)
	}

	// Verify both ct1 (v1) and ct2 (v2) decrypt successfully!
	dec1, err := vault.DecryptTemplate(ct1)
	if err != nil || !bytes.Equal(dec1, payload) {
		t.Fatalf("failed to decrypt ciphertext encrypted with key v1: %v", err)
	}

	dec2, err := vault.DecryptTemplate(ct2)
	if err != nil || !bytes.Equal(dec2, payload) {
		t.Fatalf("failed to decrypt ciphertext encrypted with key v2: %v", err)
	}

	// Re-encrypt ct1 so it transitions from v1 to v2
	ct1ReWrapped, err := vault.ReEncrypt(ct1)
	if err != nil {
		t.Fatalf("re-encryption failed: %v", err)
	}

	decReWrapped, err := vault.DecryptTemplate(ct1ReWrapped)
	if err != nil || !bytes.Equal(decReWrapped, payload) {
		t.Fatalf("failed to decrypt re-wrapped ciphertext: %v", err)
	}
}
