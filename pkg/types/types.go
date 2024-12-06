// pkg/types/types.go
package types

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Hash [32]byte

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

type Address [20]byte

func (a Address) String() string {
	return hex.EncodeToString(a[:])
}

type ValidatorAddress [20]byte

type Transaction struct {
	SourceChain      string
	DestinationChain string
	Sender          string
	Receiver        string
	Amount          uint64
	Nonce           uint64
	Timestamp       time.Time
	Signature       []byte
	ValidatorSignatures map[Address][]byte
	AssetSymbol    string
}

type Block struct {
	Height        uint64
	PreviousHash  Hash
	Timestamp     time.Time
	Transactions  []Transaction
	StateRoot     Hash
	ValidatorSet  []ValidatorAddress
	Signature     []byte
}

func HashFromString(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}

func AddressFromString(s string) (Address, error) {
	var a Address
	b, err := hex.DecodeString(s)
	if err != nil {
		return a, err
	}
	copy(a[:], b)
	return a, nil
}

// pkg/core/block.go
package core

import (
    "time"
    "github.com/atlys/pkg/types"
)

type Block struct {
    Height        uint64
    PreviousHash  types.Hash
    Timestamp     time.Time
    Transactions  []types.Transaction
    StateRoot     types.Hash
    ValidatorSet  []types.ValidatorAddress
    Signature     []byte
}

func (b *Block) Hash() types.Hash {
    // Implementation of block hashing
    return types.Hash{}
}

// pkg/consensus/validator.go
package consensus

import (
    "sync"
    "github.com/atlys/pkg/types"
)

type ValidatorSet struct {
    mu         sync.RWMutex
    validators map[types.ValidatorAddress]*Validator
    power      uint64
}

type Validator struct {
    Address    types.ValidatorAddress
    PublicKey  []byte
    Power      uint64
    Reputation uint32
}

func NewValidatorSet() *ValidatorSet {
    return &ValidatorSet{
        validators: make(map[types.ValidatorAddress]*Validator),
    }
}

func (vs *ValidatorSet) AddValidator(v *Validator) error {
    vs.mu.Lock()
    defer vs.mu.Unlock()
    
    vs.validators[v.Address] = v
    vs.power += v.Power
    return nil
}

// pkg/bridge/bridge.go
package bridge

import (
    "context"
    "sync"
    "github.com/atlys/pkg/types"
)

type Bridge struct {
    mu            sync.RWMutex
    chains        map[string]*ChainConnection
    pendingTx     map[types.Hash]*types.Transaction
    validatorSet  *consensus.ValidatorSet
}

type ChainConnection struct {
    ChainID     string
    Connection  interface{} // Chain-specific connection
    LastBlock   uint64
}

func NewBridge(vs *consensus.ValidatorSet) *Bridge {
    return &Bridge{
        chains:       make(map[string]*ChainConnection),
        pendingTx:    make(map[types.Hash]*types.Transaction),
        validatorSet: vs,
    }
}

func (b *Bridge) ProcessCrossChainTx(ctx context.Context, tx *types.Transaction) error {
    // Implement cross-chain transaction processing
    return nil
}

// cmd/atlysd/main.go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/atlys/pkg/consensus"
    "github.com/atlys/pkg/bridge"
    "github.com/atlys/internal/config"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Initialize validator set
    validatorSet := consensus.NewValidatorSet()

    // Initialize bridge
    bridge := bridge.NewBridge(validatorSet)

    // Start services
    go startServices(ctx, cfg)

    // Wait for interrupt signal
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    // Graceful shutdown
    cancel()
}

func startServices(ctx context.Context, cfg *config.Config) error {
    // Implement service startup
    return nil
}