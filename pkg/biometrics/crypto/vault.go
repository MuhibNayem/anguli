package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

var (
	ErrInvalidCiphertext = errors.New("ciphertext is too short or malformed")
)

// Vault handles envelope encryption of biometric records using AES-256-GCM
// with support for zero-downtime key rotation and multi-version key management.
type Vault struct {
	mu           sync.RWMutex
	primaryKeyID uint8
	keys         map[uint8][]byte
}

// NewVault creates a new cryptographic vault with a 32-byte AES-256 key.
func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes (got %d)", len(key))
	}
	return &Vault{
		primaryKeyID: 1,
		keys: map[uint8][]byte{
			1: key,
		},
	}, nil
}

// AddKey adds a new key version into the vault for rotation.
func (v *Vault) AddKey(keyID uint8, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be exactly 32 bytes (got %d)", len(key))
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys[keyID] = key
	return nil
}

// RotatePrimaryKey sets the primary active key version used for new encryptions.
func (v *Vault) RotatePrimaryKey(newKeyID uint8) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.keys[newKeyID]; !exists {
		return fmt.Errorf("key ID %d not found in vault keys", newKeyID)
	}
	v.primaryKeyID = newKeyID
	return nil
}

// EncryptTemplate encrypts a raw byte payload using AES-256-GCM with a fresh random nonce.
func (v *Vault) EncryptTemplate(plaintext []byte) ([]byte, error) {
	v.mu.RLock()
	key := v.keys[v.primaryKeyID]
	kid := v.primaryKeyID
	v.mu.RUnlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to init AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// Payload layout: [kid (1 byte) | nonce (12 bytes) | ciphertext+tag]
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 1+len(nonce)+len(ciphertext))
	result[0] = kid
	copy(result[1:1+len(nonce)], nonce)
	copy(result[1+len(nonce):], ciphertext)
	return result, nil
}

// DecryptTemplate decrypts an AES-256-GCM ciphertext payload, supporting multi-key rotation and legacy formats.
func (v *Vault) DecryptTemplate(ciphertext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// 1. Try tagged key format: [kid (1 byte) | nonce (12 bytes) | ciphertext]
	const minTaggedLen = 1 + 12 + 16 // 29 bytes
	if len(ciphertext) >= minTaggedLen {
		kid := ciphertext[0]
		if key, exists := v.keys[kid]; exists {
			block, err := aes.NewCipher(key)
			if err == nil {
				gcm, err := cipher.NewGCM(block)
				if err == nil {
					nonceSize := gcm.NonceSize()
					if len(ciphertext) >= 1+nonceSize+16 {
						nonce := ciphertext[1 : 1+nonceSize]
						actualCiphertext := ciphertext[1+nonceSize:]
						plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
						if err == nil {
							return plaintext, nil
						}
					}
				}
			}
		}
	}

	// 2. Legacy untagged format fallback: [nonce (12 bytes) | ciphertext]
	for _, key := range v.keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize+16 {
			continue
		}
		nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, errors.New("decryption failed: no valid key could authenticate ciphertext")
}

// ReEncrypt decrypts an existing ciphertext and re-wraps it under the latest primary key.
func (v *Vault) ReEncrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := v.DecryptTemplate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt during re-encryption: %w", err)
	}
	return v.EncryptTemplate(plaintext)
}

// TransformCancelable applies a cryptographically secure keyed non-linear transformation
// to minutiae features using HMAC-SHA256, fulfilling ISO/IEC 24745 unlinkability and revocability.
func TransformCancelable(x, y uint16, angle float64, salt string) (uint16, uint16, float64) {
	h := hmac.New(sha256.New, []byte(salt))
	var coordBuf [4]byte
	binary.BigEndian.PutUint16(coordBuf[0:2], x)
	binary.BigEndian.PutUint16(coordBuf[2:4], y)
	h.Write(coordBuf[:])
	digest := h.Sum(nil)

	// Non-linear coordinate and orientation projection
	randX := binary.BigEndian.Uint16(digest[0:2])
	randY := binary.BigEndian.Uint16(digest[2:4])
	randPhase := float64(binary.BigEndian.Uint16(digest[4:6])) / 65536.0 * 2.0 * math.Pi

	newX := (x ^ (randX % 500)) % 500
	newY := (y ^ (randY % 500)) % 500
	newAngle := math.Mod(angle+randPhase, 2.0*math.Pi)
	if newAngle < 0 {
		newAngle += 2.0 * math.Pi
	}

	return newX, newY, newAngle
}
