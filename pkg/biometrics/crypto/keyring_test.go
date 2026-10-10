package crypto

import (
	"strings"
	"testing"
)

// setEnv sets the keyring variables for one test and restores them afterwards.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
	// Explicitly clear the others so a developer's real environment cannot
	// make a test pass or fail for the wrong reason.
	for _, k := range []string{EnvMasterKey, EnvMasterKeyID, EnvMasterKeyPrevious} {
		if _, ok := kv[k]; !ok {
			t.Setenv(k, "")
		}
	}
}

const hexA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const hexB = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
const hexC = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

func TestLoadVaultFromEnv_SingleKey(t *testing.T) {
	setEnv(t, map[string]string{EnvMasterKey: hexA})
	v, err := LoadVaultFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if v.PrimaryKeyID() != defaultMasterKeyID {
		t.Errorf("primary = %d, want %d", v.PrimaryKeyID(), defaultMasterKeyID)
	}
	if got := v.KeyIDs(); len(got) != 1 || got[0] != 1 {
		t.Errorf("key ids = %v, want [1]", got)
	}
}

// TestLoadVaultFromEnv_RotationKeepsOldKeysDecryptable is the whole point of
// the feature: after rotating, records written under the previous key must
// still decrypt, or rotation means re-enrolling everyone.
func TestLoadVaultFromEnv_RotationKeepsOldKeysDecryptable(t *testing.T) {
	setEnv(t, map[string]string{EnvMasterKey: hexA})
	before, err := LoadVaultFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("enrolled template payload")
	ct, err := before.EncryptTemplate(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := KeyIDOf(ct); kid != 1 {
		t.Fatalf("new template written under key id %d, want 1", kid)
	}

	// Rotate: key 2 becomes primary, key 1 becomes decrypt-only.
	setEnv(t, map[string]string{
		EnvMasterKey:         hexB,
		EnvMasterKeyID:       "2",
		EnvMasterKeyPrevious: "1:" + hexA,
	})
	after, err := LoadVaultFromEnv()
	if err != nil {
		t.Fatalf("load rotated keyring: %v", err)
	}
	if after.PrimaryKeyID() != 2 {
		t.Errorf("primary = %d, want 2", after.PrimaryKeyID())
	}

	// The old record must still be readable.
	got, err := after.DecryptTemplate(ct)
	if err != nil {
		t.Fatalf("template written before rotation no longer decrypts: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted %q, want %q", got, plaintext)
	}

	// And it must be flagged as needing migration.
	if !after.NeedsReEncryption(ct) {
		t.Error("a record on the old key must be reported as needing rotation")
	}

	// Re-encrypting moves it onto the primary key.
	reWrapped, err := after.ReEncrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := KeyIDOf(reWrapped); kid != 2 {
		t.Errorf("re-encrypted record has key id %d, want 2", kid)
	}
	if after.NeedsReEncryption(reWrapped) {
		t.Error("a record re-encrypted onto the primary must not be flagged again")
	}
	back, err := after.DecryptTemplate(reWrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(plaintext) {
		t.Fatalf("round-trip changed the payload: %q", back)
	}
}

func TestLoadVaultFromEnv_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing master key", map[string]string{}, "mandatory"},
		{"short key", map[string]string{EnvMasterKey: "abcd"}, "64 hex"},
		{"bad hex", map[string]string{EnvMasterKey: strings.Repeat("zz", 32)}, "hex"},
		{"bad key id", map[string]string{EnvMasterKey: hexA, EnvMasterKeyID: "999"}, "0-255"},
		{"non numeric key id", map[string]string{EnvMasterKey: hexA, EnvMasterKeyID: "two"}, "0-255"},
		{"previous without colon", map[string]string{EnvMasterKey: hexA, EnvMasterKeyPrevious: hexB}, "kid:hex"},
		{"previous bad id", map[string]string{EnvMasterKey: hexA, EnvMasterKeyPrevious: "x:" + hexB}, "0-255"},
		{"previous short key", map[string]string{EnvMasterKey: hexA, EnvMasterKeyPrevious: "2:abcd"}, "64 hex"},
		{"previous duplicate id", map[string]string{EnvMasterKey: hexA, EnvMasterKeyPrevious: "2:" + hexB + ",2:" + hexC}, "duplicate"},
		{"previous collides with primary", map[string]string{EnvMasterKey: hexA, EnvMasterKeyPrevious: "1:" + hexB}, "already assigned"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setEnv(t, c.env)
			_, err := LoadVaultFromEnv()
			if err == nil {
				t.Fatalf("expected an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// TestLoadVaultFromEnv_AcceptsRawKeyBytes covers the development form.
func TestLoadVaultFromEnv_AcceptsRawKeyBytes(t *testing.T) {
	raw := strings.Repeat("k", 32)
	setEnv(t, map[string]string{EnvMasterKey: raw})
	if _, err := LoadVaultFromEnv(); err != nil {
		t.Fatalf("raw 32-byte key must be accepted: %v", err)
	}
}

// TestKeyringDescriptionNeverLeaksKeyMaterial: this string goes into startup
// logs, so a key appearing in it would be a key in the log aggregator.
func TestKeyringDescriptionNeverLeaksKeyMaterial(t *testing.T) {
	setEnv(t, map[string]string{
		EnvMasterKey:         hexA,
		EnvMasterKeyID:       "7",
		EnvMasterKeyPrevious: "1:" + hexB + ",2:" + hexC,
	})
	v, err := LoadVaultFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	d := v.KeyringDescription()
	for _, secret := range []string{hexA, hexB, hexC,
		hexA[:16], hexB[:16], hexC[:16]} {
		if strings.Contains(d, secret) {
			t.Fatalf("description %q leaks key material", d)
		}
	}
	if !strings.Contains(d, "7(primary)") {
		t.Errorf("description %q should mark the primary key", d)
	}
	if !strings.Contains(d, "1(decrypt-only)") || !strings.Contains(d, "2(decrypt-only)") {
		t.Errorf("description %q should list decrypt-only keys", d)
	}
}

// TestNeedsReEncryptionTreatsUntaggedAsPending: records written before the kid
// byte existed can be decrypted with any key, so leaving them unrotated keeps
// them permanently ambiguous.
func TestNeedsReEncryptionTreatsUntaggedAsPending(t *testing.T) {
	setEnv(t, map[string]string{EnvMasterKey: hexA})
	v, err := LoadVaultFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !v.NeedsReEncryption([]byte("no key id here at all")) {
		t.Error("an untagged payload must be reported as needing rotation")
	}
}

// TestRotationOfMultipleGenerations: two rotations in a row, with records from
// each generation still readable. This is what happens in practice, since
// rotations are years apart and records outlive them.
func TestRotationOfMultipleGenerations(t *testing.T) {
	gen1, err := NewVault(mustKey(t, hexA))
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := gen1.EncryptTemplate([]byte("generation one"))

	gen2, err := NewVault(mustKey(t, hexB))
	if err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(1, mustKey(t, hexA)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(1); err != nil {
		t.Fatal(err)
	}
	if err := gen2.AddKey(2, mustKey(t, hexB)); err != nil {
		t.Fatal(err)
	}
	if err := gen2.RotatePrimaryKey(2); err != nil {
		t.Fatal(err)
	}
	p2, _ := gen2.EncryptTemplate([]byte("generation two"))

	setEnv(t, map[string]string{
		EnvMasterKey:         hexC,
		EnvMasterKeyID:       "3",
		EnvMasterKeyPrevious: "1:" + hexA + ",2:" + hexB,
	})
	gen3, err := LoadVaultFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	for name, ct := range map[string][]byte{"gen1": p1, "gen2": p2} {
		if _, err := gen3.DecryptTemplate(ct); err != nil {
			t.Errorf("%s record unreadable after two rotations: %v", name, err)
		}
		if !gen3.NeedsReEncryption(ct) {
			t.Errorf("%s record should be flagged for migration", name)
		}
	}
}

func mustKey(t *testing.T, s string) []byte {
	t.Helper()
	k, err := decodeKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
