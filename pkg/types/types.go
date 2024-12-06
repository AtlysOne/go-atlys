package types

import (
	"encoding/hex"
	"time"
)

// Hash represents a 32-byte hash
type Hash [32]byte

// String returns the hex string representation of the hash
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Address represents a 20-byte address
type Address [20]byte

// String returns the hex string representation of the address
func (a Address) String() string {
	return hex.EncodeToString(a[:])
}

// ValidatorAddress represents a validator's address
type ValidatorAddress [20]byte

// Transaction represents a cross-chain transaction
type Transaction struct {
	Version             uint32
	SourceChain         string
	DestinationChain    string
	Sender              Address
	Receiver            Address
	Amount              uint64
	Nonce               uint64
	Timestamp           time.Time
	Data                []byte
	Gas                 uint64
	GasPrice            uint64
	Signature           []byte
	ValidatorSignatures map[Address][]byte
	AssetSymbol         string
}

// Block represents a block in the chain
type Block struct {
	Height        uint64
	PreviousHash  Hash
	Timestamp     time.Time
	Transactions  []Transaction
	StateRoot     Hash
	ValidatorSet  []ValidatorAddress
	Signature     []byte
	TxRoot        Hash
	ValidatorRoot Hash
}

// HashFromString converts a hex string to Hash
func HashFromString(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}

// AddressFromString converts a hex string to Address
func AddressFromString(s string) (Address, error) {
	var a Address
	b, err := hex.DecodeString(s)
	if err != nil {
		return a, err
	}
	copy(a[:], b)
	return a, nil
}

// ValidatorAddressFromString converts a hex string to ValidatorAddress
func ValidatorAddressFromString(s string) (ValidatorAddress, error) {
	var v ValidatorAddress
	b, err := hex.DecodeString(s)
	if err != nil {
		return v, err
	}
	copy(v[:], b)
	return v, nil
}
