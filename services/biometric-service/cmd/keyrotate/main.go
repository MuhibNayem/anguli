// Command keyrotate re-encrypts enrolled biometric templates onto the
// current primary encryption key.
//
// It exists because the data-encryption key for enrolled fingerprints is the
// one secret whose compromise is unrecoverable and unskippable. Everything else
// in this platform can be rotated with a rolling restart; a leaked template
// key exposes every enrolled person in the facility, and the only remedy
// without this command is re-enrolling all of them.
//
// Before this existed, rotating the key meant hand-written scripts, because
// the vault could hold several keys but nothing populated it from the
// environment and nothing walked the store. Both halves are now here.
//
// Usage:
//
//	keyrotate [flags]
//
// Flags:
//
//	-dry-run     report what would change and write nothing (default true)
//	-apply       perform the migration
//
// A rotation is always a two-step operation:
//
//  1. Start with BOTH keys present. Add the new key as MASTER_KEY_PREVIOUS and
//     re-run with -dry-run to see how many templates still sit on an old key.
//  2. Run with -apply. Templates are decrypted with whichever key the envelope
//     names and re-encrypted under the current primary.
//  3. Only then make the new key the sole MASTER_KEY and drop MASTER_KEY_PREVIOUS.
//
// Step 3 must be last, and only after the dry run reports zero remaining. A
// key removed while templates still reference it makes those templates
// permanently unreadable - there is no recovery path, because the data is the
// only copy.
//
// Every write is verified by decrypting what was just written before moving
// on. A rotation that half-succeeds is worse than one that fails loudly.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/store"
	sqlstore "finger-scanner/services/biometric-service/internal/adapters/sqlstore"
)

func main() {
	// Neither flag defaults to a dry run, because that is the safe outcome: an
	// operator who mistypes should learn what would change, not silently rewrite
	// every enrolled template. -dry-run is therefore false by default rather
	// than true, so that -apply on its own is not mistaken for both flags.
	dryRun := flag.Bool("dry-run", false, "report what would change without writing (default when -apply is absent)")
	apply := flag.Bool("apply", false, "perform the migration")
	flag.Parse()

	if *dryRun && *apply {
		fmt.Fprintln(os.Stderr, "choose exactly one of -dry-run or -apply")
		os.Exit(2)
	}
	if !*dryRun && !*apply {
		*dryRun = true
	}
	if err := run(context.Background(), *dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "rotation failed: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dryRun bool) error {
	vault, err := crypto.LoadVaultFromEnv()
	if err != nil {
		return fmt.Errorf("load keyring: %w", err)
	}
	fmt.Printf("keyring: %s\n", vault.KeyringDescription())

	st, err := store.Open(ctx, store.FromEnv())
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	repo, err := sqlstore.New(st)
	if err != nil {
		return fmt.Errorf("build repository: %w", err)
	}

	templates, err := repo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list templates: %w", err)
	}
	if len(templates) == 0 {
		fmt.Println("no enrolled templates; nothing to rotate")
		return nil
	}

	// Count by key id first, so the operator sees the shape before anything
	// is written.
	byKey := map[uint8]int{}
	needs := make([]int, 0, len(templates))
	for i, t := range templates {
		kid, tagged := crypto.KeyIDOf(t.EncryptedPayload)
		if !tagged {
			kid = 0 // legacy untagged payload
		}
		byKey[kid]++
		if vault.NeedsReEncryption(t.EncryptedPayload) {
			needs = append(needs, i)
		}
	}

	fmt.Printf("enrolled templates: %d\n", len(templates))
	for _, kid := range sortedKeys(byKey) {
		label := fmt.Sprintf("%d", kid)
		if kid == 0 {
			label = "untagged/legacy"
		}
		if kid == vault.PrimaryKeyID() {
			label += " (current)"
		}
		fmt.Printf("  key %-18s %d\n", label, byKey[kid])
	}
	fmt.Printf("templates needing rotation: %d\n", len(needs))

	if len(needs) == 0 {
		fmt.Println("nothing to do; every template is on the current primary key")
		return nil
	}
	if dryRun {
		fmt.Println("\n(dry run) no changes written. Re-run with -apply to migrate.")
		return nil
	}

	start := time.Now()
	migrated := 0
	for n, i := range needs {
		t := templates[i]

		plaintext, err := vault.DecryptTemplate(t.EncryptedPayload)
		if err != nil {
			return fmt.Errorf("template %s/%d: decrypt before rotation: %w", t.EmployeeID, t.Position, err)
		}
		reWrapped, err := vault.EncryptTemplate(plaintext)
		if err != nil {
			return fmt.Errorf("template %s/%d: re-encrypt: %w", t.EmployeeID, t.Position, err)
		}

		// Verify before writing. If the new envelope cannot be read back with
		// the same vault, writing it would destroy the only copy.
		verify, err := vault.DecryptTemplate(reWrapped)
		if err != nil {
			return fmt.Errorf("template %s/%d: re-encrypted payload does not decrypt back: %w",
				t.EmployeeID, t.Position, err)
		}
		if string(verify) != string(plaintext) {
			return fmt.Errorf("template %s/%d: round-trip changed the template payload", t.EmployeeID, t.Position)
		}

		t.EncryptedPayload = reWrapped
		if err := repo.Save(ctx, t); err != nil {
			return fmt.Errorf("template %s/%d: write rotated payload: %w", t.EmployeeID, t.Position, err)
		}
		migrated++
		if n%50 == 0 && n > 0 {
			fmt.Printf("  %d/%d migrated (%s elapsed)\n", n, len(needs), time.Since(start).Round(time.Second))
		}
	}

	fmt.Printf("\nrotated %d of %d templates in %s\n", migrated, len(templates), time.Since(start).Round(time.Millisecond))
	fmt.Println("verify with a fresh -dry-run before removing the old key from the keyring")
	return nil
}

func sortedKeys(m map[uint8]int) []uint8 {
	out := make([]uint8, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
