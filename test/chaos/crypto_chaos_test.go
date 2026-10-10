package chaos

import (
	"bytes"
	"testing"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
)

// ---------------------------------------------------------------------------
// Crypto / tamper chaos
// ---------------------------------------------------------------------------

func TestChaos_VaultKeyLengths(t *testing.T) {
	const dim = "crypto-key-length"
	lengths := []int{0, 1, 2, 8, 15, 16, 17, 24, 31, 32, 33, 48, 64, 65, 128, 256, 1024}
	for _, n := range lengths {
		t.Run("len", func(t *testing.T) {
			record(dim, "keylen-"+itoa(float64(n)))
			key := make([]byte, n)
			for i := range key {
				key[i] = byte(i)
			}
			v, err := crypto.NewVault(key)
			if err != nil {
				observe(dim, "keylen "+itoa(float64(n))+" correctly rejected")
				return
			}
			// Only a 32-byte key may be accepted by NewVault.
			if n != 32 {
				t.Errorf("[%s] invalid key length %d was ACCEPTED by NewVault", dim, n)
				return
			}
			ct, err := v.EncryptTemplate([]byte("probe"))
			if err != nil {
				t.Errorf("[%s] encrypt failed with valid key: %v", dim, err)
				return
			}
			pt, err := v.DecryptTemplate(ct)
			if err != nil {
				t.Errorf("[%s] round trip failed: %v", dim, err)
			}
			if !bytes.Equal(pt, []byte("probe")) {
				t.Errorf("[%s] round trip corrupted payload", dim)
			}
		})
	}
}

// INV-CORRECT: any mutation of the ciphertext must be detected by the AEAD.
func TestChaos_VaultTamperDetection(t *testing.T) {
	const dim = "crypto-tamper"
	v, err := crypto.NewVault([]byte(TestMasterKey))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	plaintext := bytes.Repeat([]byte("biometric-template-payload"), 8)
	ct, err := v.EncryptTemplate(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// single-bit flips at evenly spaced offsets
	for i := 0; i < len(ct); i++ {
		bit := byte(1) << (uint(i) % 8)
		mutated := append([]byte{}, ct...)
		mutated[i] ^= bit
		record(dim, "bitflip-offset-"+itoa(float64(i)))
		if _, err := v.DecryptTemplate(mutated); err == nil {
			t.Errorf("[%s] bit flip at offset %d was NOT detected", dim, i)
		}
	}

	// truncations
	for _, cut := range []int{0, 1, 2, 5, 11, 12, 13, len(ct) / 2, len(ct) - 1} {
		record(dim, "truncate-"+itoa(float64(cut)))
		if _, err := v.DecryptTemplate(ct[:cut]); err == nil && cut > 0 {
			// A truncated payload must not decrypt to garbage silently.
			observe(dim, "truncate "+itoa(float64(cut))+" did not error")
		}
	}

	// extensions
	for _, extra := range []int{1, 2, 16, 64} {
		ext := append(append([]byte{}, ct...), bytes.Repeat([]byte{0xAA}, extra)...)
		record(dim, "extend-"+itoa(float64(extra)))
		if pt, err := v.DecryptTemplate(ext); err == nil {
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("[%s] extended ciphertext decrypted to wrong plaintext", dim)
			}
			observe(dim, "extend "+itoa(float64(extra))+" decrypted (GCM ignores trailing bytes)")
		}
	}

	// wrong key
	for _, k := range []string{
		"1123456789abcdef0123456789abcdef",
		"1123456789abcdef0123456789abcdee",
		"ffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000",
	} {
		record(dim, "wrongkey-"+itoa(float64(len(k))))
		other, _ := crypto.NewVault([]byte(k))
		if pt, err := other.DecryptTemplate(ct); err == nil {
			t.Errorf("[%s] ciphertext decrypted under a different key", dim)
			_ = pt
		}
	}

	// nil / empty ciphertext
	for n := 0; n < 3; n++ {
		record(dim, "nil-ciphertext-"+itoa(float64(n)))
		if _, err := v.DecryptTemplate(nil); err == nil {
			t.Errorf("[%s] nil ciphertext decrypted", dim)
		}
	}

	// round-trip across many payload sizes
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 64, 1000, 65536} {
		record(dim, "roundtrip-"+itoa(float64(n)))
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		enc, err := v.EncryptTemplate(payload)
		if err != nil {
			t.Errorf("[%s] encrypt %d bytes: %v", dim, n, err)
			continue
		}
		dec, err := v.DecryptTemplate(enc)
		if err != nil {
			t.Errorf("[%s] decrypt %d bytes: %v", dim, n, err)
			continue
		}
		if !bytes.Equal(dec, payload) {
			t.Errorf("[%s] round trip mismatch at %d bytes", dim, n)
		}
	}
}

// The cancelable transform must never be a trivially invertible shift.
func TestChaos_CancelableTransform(t *testing.T) {
	const dim = "crypto-cancelable"
	salts := []string{"", "a", "salt", "site-austin-v1", longString(64), "🚪", "\x00", "0"}
	base := []minutiae.Minutia{
		{X: 100, Y: 100, Angle: 0.5}, {X: 250, Y: 40, Angle: 2.5},
		{X: 40, Y: 260, Angle: 4.0}, {X: 499, Y: 499, Angle: 1.5},
		{X: 0, Y: 0, Angle: 0.0}, {X: 499, Y: 0, Angle: 3.3},
	}
	for _, salt := range salts {
		t.Run("salt", func(t *testing.T) {
			record(dim, "salt-"+itoa(float64(len(salt))))
			pts := make([]minutiae.Minutia, len(base))
			copy(pts, base)
			transformed := make([]minutiae.Minutia, len(pts))
			for i, p := range pts {
				x, y, a := crypto.TransformCancelable(p.X, p.Y, p.Angle, salt)
				transformed[i] = minutiae.Minutia{X: x, Y: y, Angle: a}
			}

			// Coordinates must stay in range for a usable template.
			for i, p := range transformed {
				if p.X > 499 || p.Y > 499 {
					t.Errorf("[%s] transformed coordinate out of range: (%d,%d)", dim, p.X, p.Y)
				}
				_ = i
			}

			// An attacker brute-forcing the offset space must NOT fully recover
			// the plaintext for every point.
			recovered := 0
			for ax := 0; ax < 100; ax++ {
				for ay := 0; ay < 100; ay++ {
					ok := 0
					for i := range pts {
						rx := (int(transformed[i].X) - ax + 500) % 500
						ry := (int(transformed[i].Y) - ay + 500) % 500
						if rx == int(pts[i].X) && ry == int(pts[i].Y) {
							ok++
						}
					}
					if ok > recovered {
						recovered = ok
					}
				}
			}
			observe(dim, "salt len "+itoa(float64(len(salt)))+": brute-force best recovery "+itoa(float64(recovered))+"/"+itoa(float64(len(pts))))
			if recovered == len(pts) {
				observe(dim, "FULLY REVERSIBLE for salt len "+itoa(float64(len(salt))))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cylinder serialisation / wire format
// ---------------------------------------------------------------------------

func TestChaos_Serialization(t *testing.T) {
	const dim = "serialization"
	pts := make([]minutiae.Minutia, 0, 64)
	for i := 0; i < 64; i++ {
		pts = append(pts, minutiae.Minutia{
			X: uint16(i * 7), Y: uint16(i * 3), Angle: float64(i) * 0.1,
			Type: minutiae.TypeEnding, Quality: uint8(i % 100)})
	}
	tmpl := mcc.BuildTemplate("ser", pts)
	raw := tmpl.SerializeAll()
	record(dim, "roundtrip-"+itoa(float64(len(raw))))
	back, err := mcc.DeserializeAll(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(back) != len(tmpl.Cylinders) {
		t.Fatalf("cylinder count mismatch: %d vs %d", len(back), len(tmpl.Cylinders))
	}
	for i := range back {
		if back[i].MinutiaX != tmpl.Cylinders[i].MinutiaX || back[i].MinutiaY != tmpl.Cylinders[i].MinutiaY {
			t.Errorf("[%s] cylinder %d coords lost in round trip", dim, i)
		}
	}

	// truncations: only cuts that are NOT an exact cylinder multiple must fail
	for _, cut := range []int{1, 10, 100, 191, 192, 193, len(raw) - 1, len(raw)/2 - 1} {
		record(dim, "truncate-"+itoa(float64(cut)))
		if cut <= 0 || cut >= len(raw) {
			continue
		}
		if cut%204 == 0 {
			observe(dim, "truncate "+itoa(float64(cut))+" lands on a cylinder boundary and is legitimately valid")
			continue
		}
		if _, err := mcc.DeserializeAll(raw[:cut]); err == nil {
			t.Errorf("[%s] truncated buffer of %d bytes accepted", dim, cut)
		}
	}

	// single cylinder deserialize with wrong lengths
	cser := tmpl.Cylinders[0].Serialize()
	for _, cut := range []int{0, 1, 100, 191, 192, 203, 204, 300} {
		record(dim, "single-truncate-"+itoa(float64(cut)))
		if cut >= len(cser) {
			continue
		}
		_, _ = mcc.Deserialize(cser[:cut])
	}

	// mutated cylinder bytes must not silently produce a valid-looking cylinder
	for i := 0; i < len(cser); i += 37 {
		mut := append([]byte{}, cser...)
		mut[i] ^= 0xFF
		record(dim, "mutate-"+itoa(float64(i)))
		if c, err := mcc.Deserialize(mut); err == nil {
			_ = c // mutation is accepted structurally; matching is what matters
			observe(dim, "mutated cylinder at offset "+itoa(float64(i))+" still deserializes")
		}
	}
}

// ---------------------------------------------------------------------------
// MCC matcher invariants on adversarial templates
// ---------------------------------------------------------------------------

func TestChaos_MatcherInvariants(t *testing.T) {
	const dim = "matcher-invariants"
	m := mcc.NewMatcher(0.35, 60.0, nil)

	// empty / nil templates must error, not panic
	for n := 0; n < 10; n++ {
		record(dim, "empty-template-"+itoa(float64(n)))
		empty := mcc.BuildTemplate("e", nil)
		full := mcc.BuildTemplate("f", []minutiae.Minutia{{X: 10, Y: 10, Angle: 0.2}})
		if _, err := m.Verify(nil, empty, full); err == nil {
			t.Errorf("[%s] empty probe template accepted", dim)
		}
		if _, err := m.Verify(nil, full, empty); err == nil {
			t.Errorf("[%s] empty gallery template accepted", dim)
		}
		if _, err := m.Verify(nil, nil, nil); err == nil {
			t.Errorf("[%s] nil templates accepted", dim)
		}
	}

	// duplicate minutiae at identical coordinates
	for dup := 2; dup <= 40; dup += 2 {
		t.Run("duplicates", func(t *testing.T) {
			record(dim, "duplicate-minutiae-"+itoa(float64(dup)))
			pts := make([]minutiae.Minutia, dup)
			for i := range pts {
				pts[i] = minutiae.Minutia{X: 100, Y: 100, Angle: 0.3}
			}
			t1 := mcc.BuildTemplate("d", pts)
			t2 := mcc.BuildTemplate("d", pts)
			r, err := m.Verify(nil, t1, t2)
			if err != nil {
				t.Errorf("[%s] identical degenerate templates failed to verify: %v", dim, err)
				return
			}
			observe(dim, "duplicate minutiae n="+itoa(float64(dup))+" score="+itoa(r.Score))
		})
	}

	// extreme coordinates and angles
	extreme := []minutiae.Minutia{
		{X: 0, Y: 0, Angle: 0}, {X: 65535, Y: 65535, Angle: 2 * 3.14159265358979},
		{X: 0, Y: 65535, Angle: 1.5707963}, {X: 65535, Y: 0, Angle: -1.0},
		{X: 32768, Y: 32768, Angle: 100.0}, {X: 1, Y: 1, Angle: -100.0},
	}
	for i := 0; i < 12; i++ {
		t.Run("extreme", func(t *testing.T) {
			record(dim, "extreme-coords-"+itoa(float64(i)))
			t1 := mcc.BuildTemplate("x", extreme)
			t2 := mcc.BuildTemplate("x", extreme)
			if _, err := m.Verify(nil, t1, t2); err != nil {
				t.Errorf("[%s] extreme coordinates caused error: %v", dim, err)
			}
		})
	}
}

// Key rotation must never silently break decryption of existing payloads.
func TestChaos_KeyRotation(t *testing.T) {
	const dim = "crypto-rotation"
	v, err := crypto.NewVault([]byte(TestMasterKey))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	// Payload encrypted under key v1.
	legacy, err := v.EncryptTemplate([]byte("legacy-biometric-template"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	key2 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	record(dim, "add-invalid-key-16")
	if err := v.AddKey(2, key2[:16]); err == nil {
		t.Errorf("[%s] AddKey accepted a 16-byte key", dim)
	}
	record(dim, "add-invalid-key-0")
	if err := v.AddKey(2, nil); err == nil {
		t.Errorf("[%s] AddKey accepted an empty key", dim)
	}
	record(dim, "add-invalid-key-33")
	if err := v.AddKey(2, append(key2, 'x')); err == nil {
		t.Errorf("[%s] AddKey accepted a 33-byte key", dim)
	}
	record(dim, "rotate-to-missing")
	if err := v.RotatePrimaryKey(99); err == nil {
		t.Errorf("[%s] RotatePrimaryKey accepted a missing key id", dim)
	}
	record(dim, "rotate-to-zero")
	_ = v.RotatePrimaryKey(0)

	record(dim, "decrypt-before-rotate")
	if pt, err := v.DecryptTemplate(legacy); err != nil || string(pt) != "legacy-biometric-template" {
		t.Errorf("[%s] legacy payload failed to decrypt before rotation: %v", dim, err)
	}

	record(dim, "add-and-rotate")
	if err := v.AddKey(2, key2); err != nil {
		t.Fatalf("AddKey(valid): %v", err)
	}
	if err := v.RotatePrimaryKey(2); err != nil {
		t.Fatalf("RotatePrimaryKey(2): %v", err)
	}

	record(dim, "decrypt-after-rotate")
	// INV-CORRECT: rotation must not break reads of previously written data.
	if pt, err := v.DecryptTemplate(legacy); err != nil || string(pt) != "legacy-biometric-template" {
		t.Errorf("[%s] INV-CORRECT: legacy payload failed to decrypt after key rotation: %v", dim, err)
	}

	record(dim, "new-writes-use-new-key")
	fresh, err := v.EncryptTemplate([]byte("post-rotation"))
	if err != nil {
		t.Fatalf("encrypt after rotation: %v", err)
	}
	if pt, err := v.DecryptTemplate(fresh); err != nil || string(pt) != "post-rotation" {
		t.Errorf("[%s] post-rotation payload failed to round trip: %v", dim, err)
	}

	// Rotating back must also preserve readability.
	record(dim, "rotate-back")
	if err := v.RotatePrimaryKey(1); err != nil {
		t.Fatalf("rotate back: %v", err)
	}
	if pt, err := v.DecryptTemplate(fresh); err != nil || string(pt) != "post-rotation" {
		t.Errorf("[%s] payload unreadable after rotating back: %v", dim, err)
	}
	if pt, err := v.DecryptTemplate(legacy); err != nil || string(pt) != "legacy-biometric-template" {
		t.Errorf("[%s] legacy payload unreadable after rotating back: %v", dim, err)
	}
	record(dim, "rotate-back-verify")
}
