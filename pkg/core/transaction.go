package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atlys/pkg/types"
)

type Transaction struct {
	Version     uint32
	SourceChain string
	DestChain   string
	Nonce       uint64
	From        types.Address
	To          types.Address
	Amount      uint64
	Gas         uint64
	GasPrice    uint64
	Data        []byte
	Timestamp   time.Time
	Signature   []byte
}

type CrossChainData struct {
	SourceHeight uint64
	SourceHash   types.Hash
	DestHeight   uint64
	ProofData    []byte
}

func NewTransaction(
	from types.Address,
	to types.Address,
	amount uint64,
	nonce uint64,
	sourceChain string,
	destChain string,
) *Transaction {
	return &Transaction{
		Version:     1,
		SourceChain: sourceChain,
		DestChain:   destChain,
		Nonce:       nonce,
		From:        from,
		To:          to,
		Amount:      amount,
		Gas:         21000, // Base gas for standard transfer
		GasPrice:    1,     // Base gas price
		Timestamp:   time.Now().UTC(),
	}
}

func (tx *Transaction) Hash() types.Hash {
	// Create a copy without the signature
	txCopy := *tx
	txCopy.Signature = nil

	data, err := json.Marshal(txCopy)
	if err != nil {
		return types.Hash{}
	}

	hash := sha256.Sum256(data)
	return hash
}

func (tx *Transaction) Sign(privateKey []byte) error {
	hash := tx.Hash()
	signature, err := sign(privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.Signature = signature
	return nil
}

func (tx *Transaction) Verify() error {
	if tx.Version == 0 {
		return fmt.Errorf("invalid transaction version")
	}

	if tx.From == (types.Address{}) {
		return fmt.Errorf("invalid sender address")
	}

	if tx.To == (types.Address{}) {
		return fmt.Errorf("invalid recipient address")
	}

	if tx.Amount == 0 {
		return fmt.Errorf("invalid amount")
	}

	if tx.Gas < 21000 {
		return fmt.Errorf("gas too low")
	}

	if tx.GasPrice == 0 {
		return fmt.Errorf("invalid gas price")
	}

	if tx.Timestamp.After(time.Now().Add(time.Hour)) {
		return fmt.Errorf("timestamp too far in future")
	}

	if len(tx.Signature) == 0 {
		return fmt.Errorf("missing signature")
	}

	// Verify signature
	hash := tx.Hash()
	if err := verify(tx.From[:], hash[:], tx.Signature); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// Cross-chain specific validations
	if tx.SourceChain != "" || tx.DestChain != "" {
		if err := tx.verifyCrossChain(); err != nil {
			return fmt.Errorf("cross-chain verification failed: %w", err)
		}
	}

	return nil
}

func (tx *Transaction) verifyCrossChain() error {
	if tx.SourceChain == "" {
		return fmt.Errorf("missing source chain")
	}

	if tx.DestChain == "" {
		return fmt.Errorf("missing destination chain")
	}

	if tx.SourceChain == tx.DestChain {
		return fmt.Errorf("source and destination chains must be different")
	}

	var crossChainData CrossChainData
	if err := json.Unmarshal(tx.Data, &crossChainData); err != nil {
		return fmt.Errorf("invalid cross-chain data")
	}

	if crossChainData.SourceHeight == 0 {
		return fmt.Errorf("invalid source height")
	}

	if crossChainData.SourceHash == (types.Hash{}) {
		return fmt.Errorf("invalid source hash")
	}

	if len(crossChainData.ProofData) == 0 {
		return fmt.Errorf("missing proof data")
	}

	return nil
}

func (tx *Transaction) GasCost() uint64 {
	return tx.Gas * tx.GasPrice
}

func (tx *Transaction) TotalCost() uint64 {
	return tx.Amount + tx.GasCost()
}

func (tx *Transaction) Encode() ([]byte, error) {
	return json.Marshal(tx)
}

func (tx *Transaction) Decode(data []byte) error {
	return json.Unmarshal(data, tx)
}

// Helper functions

func sign(privateKey, message []byte) ([]byte, error) {
	// TODO: Implement actual signing logic using ed25519 or secp256k1
	return nil, nil
}

func verify(publicKey, message, signature []byte) error {
	// TODO: Implement actual signature verification
	return nil
}