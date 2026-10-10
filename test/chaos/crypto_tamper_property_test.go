package chaos

import (
	"testing"

	"finger-scanner/pkg/biometrics/crypto"
)

// TestCrypto_SingleBitTamperAlwaysFails is the property the vault fuzz target
// was reaching for and did not state: flipping ANY single bit of a valid
// ciphertext must break authentication, at every position.
//
// GCM authenticates the whole ciphertext, so this is a real guarantee rather
// than a probabilistic one. Checking every byte position of the envelope -
// kid, nonce and the ciphertext+tag body - is what distinguishes "the tag is
// checked" from "the nonce is skipped and only the body is authenticated".
func TestCrypto_SingleBitTamperAlwaysFails(t *testing.T) {
	v, err := crypto.NewVault([]byte(TestMasterKey))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := v.EncryptTemplate([]byte("seed-plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.DecryptTemplate(ct); err != nil {
		t.Fatalf("baseline decryption failed: %v", err)
	}

	for i := range ct {
		for _, mask := range []byte{0x01, 0x80} {
			tampered := append([]byte(nil), ct...)
			tampered[i] ^= mask
			if _, err := v.DecryptTemplate(tampered); err == nil {
				t.Fatalf("byte %d with mask %#02x authenticated after tampering", i, mask)
			}
		}
	}
}
