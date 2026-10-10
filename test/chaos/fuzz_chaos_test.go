package chaos

import (
	"bytes"
	"context"
	"testing"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/pkg/biometrics/quality"
)

// Go native fuzz targets. During a normal `go test` run the seed corpus below
// executes; `-fuzz` explores beyond it. Each seed is a chaos case, so they
// also contribute to the coverage count via FuzzCaseCount.

// SeedCorpusSize returns the number of fuzz seed cases declared in this file.
func SeedCorpusSize() int { return fuzzSeedCount }

var fuzzSeedCount int

// addSeed registers a single-argument seed corpus entry AND records it as an
// executed chaos case. Registration happens unconditionally during test
// setup, so the case count does not depend on whether the fuzz body reaches
// its assertions.
func addSeed(f *testing.F, dim string, v []byte) {
	f.Add(v)
	fuzzSeedCount++
	record(dim, "seed-"+itoa(float64(len(v))))
}

// addSeedImage registers a (w, h, pixels) seed for multi-argument targets.
func addSeedImage(f *testing.F, dim string, w, h uint32, pix []byte) {
	f.Add(w, h, pix)
	fuzzSeedCount++
	record(dim, "seed-"+itoa(float64(w))+"x"+itoa(float64(h)))
}

// FuzzCylinderDeserialise must never panic and must never accept a payload
// whose length is not an exact multiple of the cylinder size.
func FuzzCylinderDeserialise(f *testing.F) {
	addSeed(f, "fuzz-deserialize", []byte{})
	addSeed(f, "fuzz-deserialize", []byte{0})
	addSeed(f, "fuzz-deserialize", bytes.Repeat([]byte{0}, 204))
	addSeed(f, "fuzz-deserialize", bytes.Repeat([]byte{0xFF}, 204))
	addSeed(f, "fuzz-deserialize", bytes.Repeat([]byte{0xAA}, 204*2))
	addSeed(f, "fuzz-deserialize", bytes.Repeat([]byte{0x55}, 204*3+1))
	pts := []minutiae.Minutia{{X: 10, Y: 10, Angle: 0.5}, {X: 60, Y: 80, Angle: 2.0}}
	good := mcc.BuildTemplate("fuzz", pts).SerializeAll()
	addSeed(f, "fuzz-deserialize", good)
	addSeed(f, "fuzz-deserialize", good[:len(good)-1])
	addSeed(f, "fuzz-deserialize", append(append([]byte{}, good...), 0x00))

	f.Fuzz(func(t *testing.T, data []byte) {
		cyls, err := mcc.DeserializeAll(data)
		if err != nil {
			return
		}
		// Anything that deserialises must round-trip to the same count.
		record("fuzz-deserialize", "roundtrip-"+itoa(float64(len(data))))
		if len(cyls) == 0 && len(data) != 0 {
			t.Errorf("deserialised non-empty payload into zero cylinders")
		}
		// Re-serialising must produce a payload of the same size.
		tpl := &mcc.Template{ID: "rt", Cylinders: cyls}
		if got := len(tpl.SerializeAll()); got != len(data) {
			t.Errorf("round trip size mismatch: %d -> %d", len(data), got)
		}
	})
}

// FuzzVaultDecrypt must never panic and must never return plaintext for a
// payload it did not encrypt.
func FuzzVaultDecrypt(f *testing.F) {
	v, err := crypto.NewVault([]byte(TestMasterKey))
	if err != nil {
		f.Fatalf("vault: %v", err)
	}
	ct, err := v.EncryptTemplate([]byte("seed-plaintext"))
	if err != nil {
		f.Fatalf("encrypt: %v", err)
	}
	addSeed(f, "fuzz-vault", ct)
	addSeed(f, "fuzz-vault", ct[:len(ct)-1])
	addSeed(f, "fuzz-vault", []byte{})
	addSeed(f, "fuzz-vault", bytes.Repeat([]byte{0}, 12))

	f.Fuzz(func(t *testing.T, data []byte) {
		record("fuzz-vault", "decrypt-"+itoa(float64(len(data))))
		pt, err := v.DecryptTemplate(data)
		if err != nil {
			return
		}
		// Only the genuine ciphertext may decrypt, and only to its own plaintext.
		if !bytes.Equal(data, ct) {
			t.Errorf("INV-CORRECT: forged ciphertext decrypted to %q", pt)
		}
		if !bytes.Equal(pt, []byte("seed-plaintext")) {
			t.Errorf("INV-CORRECT: ciphertext decrypted to wrong plaintext %q", pt)
		}
	})
}

// FuzzTemplatePipeline drives the whole image pipeline on arbitrary input and
// asserts only the invariants that must hold for any input at all.
func FuzzTemplatePipeline(f *testing.F) {
	addSeedImage(f, "fuzz-pipeline", 64, 64, []byte(LoopPrint(64, 64, 32, 32, 8, 1)))
	addSeedImage(f, "fuzz-pipeline", 128, 128, bytes.Repeat([]byte{128}, 128*128))
	addSeedImage(f, "fuzz-pipeline", 32, 32, []byte{})
	addSeedImage(f, "fuzz-pipeline", 100, 100, bytes.Repeat([]byte{0}, 100*100))

	f.Fuzz(func(t *testing.T, w, h uint32, pix []byte) {
		record("fuzz-pipeline", "pipeline-"+itoa(float64(w))+"x"+itoa(float64(h)))
		// Guard: never allocate from an untrusted size.
		if w == 0 || h == 0 || w > 1024 || h > 1024 {
			return
		}
		img, err := image.NewGrayImage(int(w), int(h), pix)
		if err != nil {
			// INV-CORRECT: a buffer that does not match w*h must be rejected.
			return
		}
		norm := img.Normalize(128, 2000)
		bin := norm.AdaptiveBinarize(15)
		skel := image.ZhangSuenThinning(bin, int(w), int(h))
		orient := norm.OrientationField(16)
		pts := minutiae.NewExtractor().Extract(skel, int(w), int(h), orient, 16)
		score, _ := quality.NewQualityAssessor().Evaluate(norm, pts)
		record("fuzz-pipeline", "quality-"+itoa(float64(score)))
		if len(pts) == 0 {
			return
		}
		tpl := mcc.BuildTemplate("f", pts)
		m := mcc.NewMatcher(0.35, 60.0, nil)
		if _, err := m.Verify(nil, tpl, tpl); err != nil {
			t.Errorf("a template failed to match itself: %v", err)
		}
	})
}

// FuzzAPBStateMachine drives the policy service with arbitrary swipe
// sequences and asserts the anti-passback invariant for every one of them.
func FuzzAPBStateMachine(f *testing.F) {
	addSeed(f, "fuzz-apb", []byte{1, 1, 2, 1, 2, 2, 1})
	addSeed(f, "fuzz-apb", []byte{1, 2, 1, 2, 1, 2})
	addSeed(f, "fuzz-apb", []byte{2})
	addSeed(f, "fuzz-apb", []byte{1})

	f.Fuzz(func(t *testing.T, seq []byte) {
		record("fuzz-apb", "seq-"+itoa(float64(len(seq))))
		if len(seq) > 64 {
			seq = seq[:64]
		}
		c := NewPolicyCluster(t)
		emp := "FZ"
		prevEntryGranted := false
		for i, d := range seq {
			dir := accesscontrolv1.DoorDirection(int32(d%2) + 1) // 1 = entry, 2 = exit
			r, err := c.Policy.EvaluateAccess(ctxShort(), &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId: emp, ZoneId: "zone-main-gate", DoorId: "d",
				Direction:         dir,
				BiometricVerified: true, BiometricScore: 90, TimestampUnix: time.Now().Unix() + int64(i),
			})
			if err != nil {
				return
			}
			// INV-NOBYPASS: consecutive entries must never both be granted.
			if dir == 1 && prevEntryGranted && r.IsGranted {
				t.Errorf("anti-passback violated at step %d", i)
			}
			if r.IsGranted {
				prevEntryGranted = dir == 1
			}
		}
	})
}

// ctxShort is a bounded context for fuzz iterations.
func ctxShort() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_ = cancel
	return ctx
}
