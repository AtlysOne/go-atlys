// Package crypto implements cryptographic operations for ATLYS
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"github.com/atlys/pkg/types"
)

// KeyType identifies the type of cryptographic key
type KeyType uint8

const (
	KeyTypeEd25519 KeyType = iota
	KeyTypeSecp256k1
)

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
	KeyType    KeyType
	Address    types.Address
}

// KeyStore manages cryptographic keys
type KeyStore struct {
	mu       sync.RWMutex
	keys     map[types.Address]*KeyPair
	seedKeys map[string]*KeyPair // Maps seed phrase to key pair
}

// NewKeyStore creates a new instance of KeyStore
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys:     make(map[types.Address]*KeyPair),
		seedKeys: make(map[string]*KeyPair),
	}
}

// GenerateKeyPair creates a new key pair
func (ks *KeyStore) GenerateKeyPair(keyType KeyType) (*KeyPair, error) {
	switch keyType {
	case KeyTypeEd25519:
		return ks.generateEd25519KeyPair()
	case KeyTypeSecp256k1:
		return ks.generateSecp256k1KeyPair()
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}

// ImportPrivateKey imports an existing private key
func (ks *KeyStore) ImportPrivateKey(privateKeyHex string, keyType KeyType) (*KeyPair, error) {
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	switch keyType {
	case KeyTypeEd25519:
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key length")
		}
		publicKey := privateKey[32:]
		address := generateAddress(publicKey)

		keyPair := &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			KeyType:    KeyTypeEd25519,
			Address:    address,
		}

		ks.mu.Lock()
		ks.keys[address] = keyPair
		ks.mu.Unlock()

		return keyPair, nil

	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 key import
		return nil, fmt.Errorf("Secp256k1 not implemented")
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}

// ExportPrivateKey exports a private key for a given address
func (ks *KeyStore) ExportPrivateKey(address types.Address) (string, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keyPair, exists := ks.keys[address]
	if !exists {
		return "", fmt.Errorf("key not found for address: %s", address)
	}

	return hex.EncodeToString(keyPair.PrivateKey), nil
}

// GetKeyPair retrieves a key pair by address
func (ks *KeyStore) GetKeyPair(address types.Address) (*KeyPair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keyPair, exists := ks.keys[address]
	if !exists {
		return nil, fmt.Errorf("key not found for address: %s", address)
	}

	return keyPair, nil
}

// ListAddresses returns all addresses in the keystore
func (ks *KeyStore) ListAddresses() []types.Address {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	addresses := make([]types.Address, 0, len(ks.keys))
	for addr := range ks.keys {
		addresses = append(addresses, addr)
	}
	return addresses
}

// DeleteKey removes a key pair from the keystore
func (ks *KeyStore) DeleteKey(address types.Address) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if _, exists := ks.keys[address]; !exists {
		return fmt.Errorf("key not found for address: %s", address)
	}

	delete(ks.keys, address)
	return nil
}

// Internal methods

func (ks *KeyStore) generateEd25519KeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	address := generateAddress(pub)
	keyPair := &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyType:    KeyTypeEd25519,
		Address:    address,
	}

	ks.mu.Lock()
	ks.keys[address] = keyPair
	ks.mu.Unlock()

	return keyPair, nil
}

func (ks *KeyStore) generateSecp256k1KeyPair() (*KeyPair, error) {
	// TODO: Implement Secp256k1 key generation
	return nil, fmt.Errorf("Secp256k1 not implemented")
}

// Helper functions

func generateAddress(publicKey []byte) types.Address {
	// TODO: Implement proper address generation based on network type
	var address types.Address
	copy(address[:], publicKey[:20])
	return address
}

// Key operations

// Sign signs a message with a private key
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
	switch kp.KeyType {
	case KeyTypeEd25519:
		return ed25519.Sign(kp.PrivateKey, message), nil
	case KeyTypeSecp256k1:
		return nil, fmt.Errorf("Secp256k1 signing not implemented")
	default:
		return nil, fmt.Errorf("unsupported key type: %d", kp.KeyType)
	}
}

// Verify verifies a signature with a public key
func (kp *KeyPair) Verify(message, signature []byte) bool {
	switch kp.KeyType {
	case KeyTypeEd25519:
		return ed25519.Verify(kp.PublicKey, message, signature)
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 verification
		return false
	default:
		return false
	}
}

// Seed phrase support

// GenerateFromSeed generates a deterministic key pair from a seed phrase
func (ks *KeyStore) GenerateFromSeed(seed string, keyType KeyType) (*KeyPair, error) {
	if keyPair, exists := ks.seedKeys[seed]; exists {
		return keyPair, nil
	}

	// Generate deterministic entropy from seed
	entropy := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}

	// Generate key pair based on key type
	var keyPair *KeyPair
	var err error

	switch keyType {
	case KeyTypeEd25519:
		keyPair, err = ks.generateEd25519FromSeed(entropy)
	case KeyTypeSecp256k1:
		keyPair, err = ks.generateSecp256k1FromSeed(entropy)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}

	if err != nil {
		return nil, err
	}

	ks.mu.Lock()
	ks.seedKeys[seed] = keyPair
	ks.keys[keyPair.Address] = keyPair
	ks.mu.Unlock()

	return keyPair, nil
}

func (ks *KeyStore) generateEd25519FromSeed(seed []byte) (*KeyPair, error) {
	reader := NewDeterministicReader(seed)
	pub, priv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key from seed: %w", err)
	}

	address := generateAddress(pub)
	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyType:    KeyTypeEd25519,
		Address:    address,
	}, nil
}

func (ks *KeyStore) generateSecp256k1FromSeed(seed []byte) (*KeyPair, error) {
	// TODO: Implement Secp256k1 deterministic key generation
	return nil, fmt.Errorf("Secp256k1 not implemented")
}

// DeterministicReader provides deterministic randomness from a seed
type DeterministicReader struct {
	seed []byte
	pos  int
}

func NewDeterministicReader(seed []byte) *DeterministicReader {
	return &DeterministicReader{seed: seed}
}

func (r *DeterministicReader) Read(p []byte) (n int, err error) {
	// TODO: Implement proper deterministic random number generation
	copy(p, r.seed[r.pos:])
	r.pos += len(p)
	return len(p), nil
}
