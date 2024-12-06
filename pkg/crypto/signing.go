// Package crypto implements cryptographic signing operations for ATLYS
package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/atlys/pkg/types"
)

// SignatureSize defines the size of signatures in bytes
const (
	Ed25519SignatureSize    = 64
	Secp256k1SignatureSize = 65
)

// Signer interface defines the signing operations
type Signer interface {
	Sign(message []byte) ([]byte, error)
	Verify(pubKey, message, signature []byte) bool
	GetPublicKey() []byte
	GetAddress() types.Address
}

// Ed25519Signer implements Signer for Ed25519
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	address    types.Address
}

// NewEd25519Signer creates a new Ed25519 signer
func NewEd25519Signer(privateKey []byte) (*Ed25519Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	signer := &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  privateKey[32:],
	}
	signer.address = generateAddress(signer.publicKey)

	return signer, nil
}

// Sign signs a message using Ed25519
func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("empty message")
	}

	// Hash the message first
	hash := sha256.Sum256(message)
	
	// Sign the hash
	signature := ed25519.Sign(s.privateKey, hash[:])
	return signature, nil
}

// Verify verifies an Ed25519 signature
func (s *Ed25519Signer) Verify(pubKey, message, signature []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != Ed25519SignatureSize {
		return false
	}

	hash := sha256.Sum256(message)
	return ed25519.Verify(pubKey, hash[:], signature)
}

func (s *Ed25519Signer) GetPublicKey() []byte {
	return s.publicKey
}

func (s *Ed25519Signer) GetAddress() types.Address {
	return s.address
}

// MultiSigner handles multi-signature operations
type MultiSigner struct {
	threshold  uint
	publicKeys [][]byte
	keyType    KeyType
	addresses  []types.Address
}

// NewMultiSigner creates a new multi-signature handler
func NewMultiSigner(threshold uint, publicKeys [][]byte, keyType KeyType) (*MultiSigner, error) {
	if threshold == 0 || threshold > uint(len(publicKeys)) {
		return nil, errors.New("invalid threshold")
	}

	addresses := make([]types.Address, len(publicKeys))
	for i, pubKey := range publicKeys {
		addresses[i] = generateAddress(pubKey)
	}

	return &MultiSigner{
		threshold:  threshold,
		publicKeys: publicKeys,
		keyType:    keyType,
		addresses:  addresses,
	}, nil
}

// VerifyMultiSig verifies a multi-signature
func (ms *MultiSigner) VerifyMultiSig(message []byte, signatures [][]byte, signerIndexes []uint) bool {
	if uint(len(signatures)) < ms.threshold {
		return false
	}

	validSigs := uint(0)
	for i, sig := range signatures {
		if i >= len(signerIndexes) {
			break
		}

		index := signerIndexes[i]
		if index >= uint(len(ms.publicKeys)) {
			return false
		}

		var valid bool
		switch ms.keyType {
		case KeyTypeEd25519:
			signer := &Ed25519Signer{publicKey: ms.publicKeys[index]}
			valid = signer.Verify(ms.publicKeys[index], message, sig)
		case KeyTypeSecp256k1:
			// TODO: Implement Secp256k1 verification
			return false
		default:
			return false
		}

		if valid {
			validSigs++
			if validSigs >= ms.threshold {
				return true
			}
		}
	}

	return false
}

// BatchVerifier handles batch signature verification
type BatchVerifier struct {
	messages   [][]byte
	publicKeys [][]byte
	signatures [][]byte
	keyType    KeyType
}

// NewBatchVerifier creates a new batch signature verifier
func NewBatchVerifier(keyType KeyType) *BatchVerifier {
	return &BatchVerifier{
		keyType: keyType,
	}
}

// AddSignature adds a signature to the batch
func (bv *BatchVerifier) AddSignature(pubKey, message, signature []byte) error {
	if len(pubKey) == 0 || len(message) == 0 || len(signature) == 0 {
		return errors.New("invalid input")
	}

	bv.publicKeys = append(bv.publicKeys, pubKey)
	bv.messages = append(bv.messages, message)
	bv.signatures = append(bv.signatures, signature)
	return nil
}

// Verify performs batch signature verification
func (bv *BatchVerifier) Verify() bool {
	if len(bv.messages) == 0 {
		return false
	}

	switch bv.keyType {
	case KeyTypeEd25519:
		return bv.verifyEd25519Batch()
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 batch verification
		return false
	default:
		return false
	}
}

func (bv *BatchVerifier) verifyEd25519Batch() bool {
	for i := range bv.messages {
		signer := &Ed25519Signer{publicKey: bv.publicKeys[i]}
		if !signer.Verify(bv.publicKeys[i], bv.messages[i], bv.signatures[i]) {
			return false
		}
	}
	return true
}

// Signature aggregation support

// AggregateSignatures combines multiple signatures into one
func AggregateSignatures(signatures [][]byte, keyType KeyType) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, errors.New("empty signatures")
	}

	switch keyType {
	case KeyTypeEd25519:
		// Ed25519 doesn't support signature aggregation
		return nil, errors.New("Ed25519 doesn't support signature aggregation")
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 signature aggregation
		return nil, errors.New("Secp256k1 signature aggregation not implemented")
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}

// VerifyAggregateSignature verifies an aggregated signature
func VerifyAggregateSignature(pubKeys [][]byte, messages [][]byte, signature []byte, keyType KeyType) bool {
	if len(pubKeys) != len(messages) {
		return false
	}

	switch keyType {
	case KeyTypeEd25519:
		// Ed25519 doesn't support signature aggregation
		return false
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 aggregate signature verification
		return false
	default:
		return false
	}
}

// Utility functions

// SignHash signs a pre-computed hash
func SignHash(privateKey []byte, hash []byte, keyType KeyType) ([]byte, error) {
	switch keyType {
	case KeyTypeEd25519:
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid private key size")
		}
		return ed25519.Sign(privateKey, hash), nil
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 hash signing
		return nil, errors.New("Secp256k1 not implemented")
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}

// VerifyHashSignature verifies a signature on a pre-computed hash
func VerifyHashSignature(pubKey, hash, signature []byte, keyType KeyType) bool {
	switch keyType {
	case KeyTypeEd25519:
		if len(pubKey) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(pubKey, hash, signature)
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 hash signature verification
		return false
	default:
		return false
	}
}

// DeriveKey derives a new key from a master key and index
func DeriveKey(masterKey []byte, index uint32, keyType KeyType) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("empty master key")
	}

	// Create HMAC from master key
	mac := hmac.New(sha512.New, masterKey)
	
	// Add index to data
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	mac.Write(indexBytes)

	// Generate derived key
	derivedKey := mac.Sum(nil)

	switch keyType {
	case KeyTypeEd25519:
		if len(derivedKey) < ed25519.PrivateKeySize {
			return nil, errors.New("insufficient derived key length")
		}
		return derivedKey[:ed25519.PrivateKeySize], nil
	case KeyTypeSecp256k1:
		// TODO: Implement Secp256k1 key derivation
		return nil, errors.New("Secp256k1 not implemented")
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}