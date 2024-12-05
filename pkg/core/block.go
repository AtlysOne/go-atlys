package core

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atlys/pkg/types"
)

type Block struct {
	Height        uint64
	Timestamp     time.Time
	PreviousHash  types.Hash
	Transactions  []types.Transaction
	StateRoot     types.Hash
	ValidatorSet  []types.ValidatorAddress
	Signature     []byte
	Hash          types.Hash
}

type BlockHeader struct {
	Height        uint64
	Timestamp     time.Time
	PreviousHash  types.Hash
	TxRoot        types.Hash
	StateRoot     types.Hash
	ValidatorRoot types.Hash
}

func NewBlock(height uint64, previousHash types.Hash, transactions []types.Transaction) *Block {
	block := &Block{
		Height:       height,
		Timestamp:    time.Now().UTC(),
		PreviousHash: previousHash,
		Transactions: transactions,
	}
	block.Hash = block.CalculateHash()
	return block
}

func (b *Block) CalculateHash() types.Hash {
	header := b.GetHeader()
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return types.Hash{}
	}

	hash := sha256.Sum256(headerBytes)
	return hash
}

func (b *Block) GetHeader() BlockHeader {
	return BlockHeader{
		Height:        b.Height,
		Timestamp:     b.Timestamp,
		PreviousHash:  b.PreviousHash,
		TxRoot:        b.calculateTxRoot(),
		StateRoot:     b.StateRoot,
		ValidatorRoot: b.calculateValidatorRoot(),
	}
}

func (b *Block) calculateTxRoot() types.Hash {
	txHashes := make([][]byte, len(b.Transactions))
	for i, tx := range b.Transactions {
		txHash := tx.Hash()
		txHashes[i] = txHash[:]
	}
	return merkleRoot(txHashes)
}

func (b *Block) calculateValidatorRoot() types.Hash {
	validatorBytes := make([][]byte, len(b.ValidatorSet))
	for i, validator := range b.ValidatorSet {
		validatorBytes[i] = validator[:]
	}
	return merkleRoot(validatorBytes)
}

func (b *Block) Verify() error {
	// Verify block hash
	if calculatedHash := b.CalculateHash(); calculatedHash != b.Hash {
		return fmt.Errorf("invalid block hash")
	}

	// Verify timestamp
	if b.Timestamp.After(time.Now().Add(time.Hour)) {
		return fmt.Errorf("block timestamp too far in future")
	}

	// Verify transactions
	for _, tx := range b.Transactions {
		if err := tx.Verify(); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}

	// Verify signature if present
	if len(b.Signature) > 0 {
		if err := b.verifySignature(); err != nil {
			return fmt.Errorf("invalid signature: %w", err)
		}
	}

	return nil
}

func (b *Block) Sign(privKey []byte) error {
	header := b.GetHeader()
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	signature, err := sign(privKey, headerBytes)
	if err != nil {
		return err
	}

	b.Signature = signature
	return nil
}

func (b *Block) verifySignature() error {
	header := b.GetHeader()
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	return verify(b.ValidatorSet[0][:], headerBytes, b.Signature)
}

func (b *Block) Encode() ([]byte, error) {
	return json.Marshal(b)
}

func (b *Block) Decode(data []byte) error {
	return json.Unmarshal(data, b)
}

func (b *Block) Size() uint64 {
	encoded, _ := b.Encode()
	return uint64(len(encoded))
}

// Helper functions

func merkleRoot(items [][]byte) types.Hash {
	if len(items) == 0 {
		return types.Hash{}
	}
	if len(items) == 1 {
		hash := sha256.Sum256(items[0])
		return hash
	}

	var level [][]byte
	for i := 0; i < len(items); i += 2 {
		if i+1 < len(items) {
			combined := append(items[i], items[i+1]...)
			hash := sha256.Sum256(combined)
			level = append(level, hash[:])
		} else {
			level = append(level, items[i])
		}
	}
	
	hash := merkleRoot(level)
	return hash
}

func sign(privKey, message []byte) ([]byte, error) {
	// Implement signing logic
	return nil, nil
}

func verify(pubKey, message, signature []byte) error {
	// Implement verification logic
	return nil
}