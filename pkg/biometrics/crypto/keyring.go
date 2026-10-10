package crypto

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Keyring loading.
//
// The vault has supported multiple key versions since it was written, and the
// ciphertext envelope has carried a key id from the start. What never
// happened is a way to POPULATE it: the biometric service loaded a single
// MASTER_KEY at startup and that was the whole keyring. AddKey and
// RotatePrimaryKey were called only from tests.
//
// The consequence is that rotating the data-encryption key - the thing every
// enterprise policy eventually demands, because a compromised key otherwise
// exposes every enrolled template - meant one of two unacceptable outcomes:
// re-encrypting by hand with bespoke scripts, or re-enrolling every employee
// in the building.
//
// The environment contract:
//
//	MASTER_KEY             required. The primary key: new encryptions use it.
//	MASTER_KEY_ID          optional. Key id assigned to MASTER_KEY. Default 1.
//	MASTER_KEY_PREVIOUS    optional. "kid:hex,kid:hex,..." Decryption only.
//
// Old keys stay decryptable while MASTER_KEY is the primary, so rotation needs
// no downtime and no re-enrollment. DecryptTemplate dispatches on the key id
// embedded in the envelope, so this is enough to read records written under
// any previously-active key.

// Environment variable names, exported so operators and tests do not spell
// them differently from the implementation.
const (
	EnvMasterKey         = "MASTER_KEY"
	EnvMasterKeyID       = "MASTER_KEY_ID"
	EnvMasterKeyPrevious = "MASTER_KEY_PREVIOUS"
)

const defaultMasterKeyID uint8 = 1

// LoadVaultFromEnv builds a vault from the keyring environment variables.
//
// Failure is always fatal to the caller rather than a degraded vault: a
// service that silently starts with one key because the previous-key list had
// a typo would fail to decrypt enrolled templates much later, at the worst
// possible moment, and the error would name a record rather than a
// configuration mistake.
func LoadVaultFromEnv() (*Vault, error) {
	hexKey := strings.TrimSpace(os.Getenv(EnvMasterKey))
	if hexKey == "" {
		return nil, fmt.Errorf("%s environment variable is mandatory and missing", EnvMasterKey)
	}

	key, err := decodeKey(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvMasterKey, err)
	}

	masterID, err := masterKeyID()
	if err != nil {
		return nil, err
	}

	// Built directly rather than through NewVault, which registers its key
	// under the hardcoded id 1. Going through it and then re-adding under
	// masterID would leave the master key present under BOTH ids whenever
	// MASTER_KEY_ID was not 1 - so a record encrypted under id 1 during an
	// earlier rotation would suddenly decrypt with the new master key.
	v := &Vault{
		primaryKeyID: masterID,
		keys:         map[uint8][]byte{masterID: key},
	}

	previous, err := parsePreviousKeys(os.Getenv(EnvMasterKeyPrevious))
	if err != nil {
		return nil, err
	}
	for _, k := range previous {
		if k.id == masterID {
			return nil, fmt.Errorf(
				"%s: key id %d is already assigned to %s; give the rotated key a new id",
				EnvMasterKeyPrevious, masterID, EnvMasterKey)
		}
		if _, clash := v.keys[k.id]; clash {
			return nil, fmt.Errorf("%s: duplicate key id %d", EnvMasterKeyPrevious, k.id)
		}
		v.keys[k.id] = k.key
	}

	return v, nil
}

type previousKey struct {
	id  uint8
	key []byte
}

// masterKeyID reads MASTER_KEY_ID, defaulting to 1.
func masterKeyID() (uint8, error) {
	raw := strings.TrimSpace(os.Getenv(EnvMasterKeyID))
	if raw == "" {
		return defaultMasterKeyID, nil
	}
	n, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer 0-255 (got %q): %w", EnvMasterKeyID, raw, err)
	}
	return uint8(n), nil
}

// parsePreviousKeys reads "kid:hex,kid:hex,...".
func parsePreviousKeys(raw string) ([]previousKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	out := make([]previousKey, 0, len(parts))
	seen := make(map[uint8]bool, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idStr, keyHex, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%s: entry %q must be \"kid:hex\"", EnvMasterKeyPrevious, part)
		}
		id, err := strconv.ParseUint(strings.TrimSpace(idStr), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("%s: key id %q is not an integer 0-255: %w", EnvMasterKeyPrevious, idStr, err)
		}
		key, err := decodeKey(keyHex)
		if err != nil {
			return nil, fmt.Errorf("%s: key id %d: %w", EnvMasterKeyPrevious, id, err)
		}
		if seen[uint8(id)] {
			return nil, fmt.Errorf("%s: duplicate key id %d", EnvMasterKeyPrevious, id)
		}
		seen[uint8(id)] = true
		out = append(out, previousKey{id: uint8(id), key: key})
	}
	return out, nil
}

// decodeKey accepts the 64-character hex form used by the deployment, and the
// raw 32-byte form accepted for local development.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 32 && !isHex(s) {
		return []byte(s), nil
	}
	if len(s) != 64 {
		return nil, fmt.Errorf("key must be 64 hex characters or 32 raw bytes (got %d characters)", len(s))
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("key is not valid hex: %w", err)
	}
	return key, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s)%2 == 0
}

// PrimaryKeyID reports which key new encryptions will use.
func (v *Vault) PrimaryKeyID() uint8 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.primaryKeyID
}

// KeyIDs lists every key the vault can decrypt with, ascending.
func (v *Vault) KeyIDs() []uint8 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	ids := make([]uint8, 0, len(v.keys))
	for id := range v.keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// KeyIDOf reports which key a stored payload was encrypted under, or false if
// the payload does not carry a key id (a pre-kid legacy record).
func KeyIDOf(ciphertext []byte) (uint8, bool) {
	if len(ciphertext) < 1 {
		return 0, false
	}
	return ciphertext[0], true
}

// NeedsReEncryption reports whether a stored payload is not protected by the
// current primary key.
//
// It answers the only question an operator has before starting a rotation:
// "is there anything left to migrate?" Reporting it separately from the
// re-encrypt operation means a dry run is possible without writing anything.
func (v *Vault) NeedsReEncryption(ciphertext []byte) bool {
	kid, tagged := KeyIDOf(ciphertext)
	if !tagged {
		// Untagged legacy payloads are decryptable with any key and must be
		// migrated, or they stay ambiguous forever.
		return true
	}
	return kid != v.PrimaryKeyID()
}

// KeyringDescription renders a human-readable summary for startup logs.
//
// It never includes key material. Operators need to see WHICH keys are loaded
// and WHICH is primary, because a misconfigured rotation that silently loaded
// the wrong primary is otherwise invisible until a template fails to decrypt.
func (v *Vault) KeyringDescription() string {
	ids := v.KeyIDs()
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == v.PrimaryKeyID() {
			names = append(names, fmt.Sprintf("%d(primary)", id))
		} else {
			names = append(names, fmt.Sprintf("%d(decrypt-only)", id))
		}
	}
	return fmt.Sprintf("keys=[%s] primary=%d", strings.Join(names, " "), v.PrimaryKeyID())
}
