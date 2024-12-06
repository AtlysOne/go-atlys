// Package consensus implements the validator functionality for ATLYS
package consensus

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/atlys/pkg/core"
	"github.com/atlys/pkg/types"
)

// ValidatorStatus represents the current state of a validator
type ValidatorStatus int

const (
	StatusInactive ValidatorStatus = iota
	StatusActive
	StatusJailing
	StatusJailed
	StatusSlashed
)

// Validator represents a validator node in the ATLYS network
type Validator struct {
	mu             sync.RWMutex
	address        types.Address
	publicKey      ed25519.PublicKey
	privateKey     ed25519.PrivateKey
	status         ValidatorStatus
	power          uint64
	reputation     uint32
	delegatedStake uint64
	config         *ValidatorConfig
	stats          *ValidatorStats
}

// ValidatorConfig contains configuration parameters for the validator
type ValidatorConfig struct {
	MinStake          uint64
	MaxStake          uint64
	UnbondingPeriod   time.Duration
	SlashingThreshold uint32
	ReputationDecay   float64
	JailDuration      time.Duration
	MaxMissedBlocks   uint32
	BlockTimeout      time.Duration
}

// ValidatorStats tracks validator performance metrics
type ValidatorStats struct {
	totalBlocks        uint64
	proposedBlocks     uint64
	validatedBlocks    uint64
	missedBlocks       uint32
	slashingEvents     uint32
	lastProposedBlock  time.Time
	lastValidatedBlock time.Time
	uptime             time.Duration
	startTime          time.Time
}

// NewValidator creates a new validator instance
func NewValidator(config *ValidatorConfig) (*Validator, error) {
	// Generate validator keypair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate validator keys: %w", err)
	}

	return &Validator{
		publicKey:  pub,
		privateKey: priv,
		status:     StatusInactive,
		reputation: 100, // Start with maximum reputation
		config:     config,
		stats:      newValidatorStats(),
	}, nil
}

// Start initializes the validator and begins participating in consensus
func (v *Validator) Start(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.status != StatusInactive {
		return fmt.Errorf("validator already started")
	}

	// Verify minimum stake requirement
	if v.delegatedStake < v.config.MinStake {
		return fmt.Errorf("insufficient stake: %d < %d", v.delegatedStake, v.config.MinStake)
	}

	v.status = StatusActive
	v.stats.startTime = time.Now()

	go v.validationLoop(ctx)
	go v.reputationLoop(ctx)
	go v.monitoringLoop(ctx)

	return nil
}

// Stop gracefully stops the validator
func (v *Validator) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.status == StatusInactive {
		return fmt.Errorf("validator not active")
	}

	v.status = StatusInactive
	return nil
}

// ValidateBlock validates a proposed block
func (v *Validator) ValidateBlock(block *core.Block) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.status != StatusActive {
		return fmt.Errorf("validator not active")
	}

	// Verify block signature
	if err := v.verifyBlockSignature(block); err != nil {
		return fmt.Errorf("invalid block signature: %w", err)
	}

	// Verify transactions
	if err := v.verifyTransactions(block); err != nil {
		return fmt.Errorf("transaction verification failed: %w", err)
	}

	// Update validator stats
	v.stats.validatedBlocks++
	v.stats.lastValidatedBlock = time.Now()

	return nil
}

// ProposeBlock creates a new block proposal
func (v *Validator) ProposeBlock(transactions []types.Transaction) (*core.Block, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.status != StatusActive {
		return nil, fmt.Errorf("validator not active")
	}

	// Create new block
	block := core.NewBlock(
		v.stats.totalBlocks+1,
		nil, // Previous hash will be set by chain
		transactions,
	)

	// Sign block
	if err := v.signBlock(block); err != nil {
		return nil, fmt.Errorf("failed to sign block: %w", err)
	}

	// Update stats
	v.stats.proposedBlocks++
	v.stats.lastProposedBlock = time.Now()

	return block, nil
}

// UpdateReputation updates the validator's reputation score
func (v *Validator) UpdateReputation(delta int32) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	newRep := int32(v.reputation) + delta
	if newRep < 0 {
		newRep = 0
	} else if newRep > 100 {
		newRep = 100
	}

	v.reputation = uint32(newRep)

	// Check if validator should be jailed
	if v.reputation < v.config.SlashingThreshold {
		return v.jail()
	}

	return nil
}

// DelegateStake adds stake to the validator
func (v *Validator) DelegateStake(amount uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	newStake := v.delegatedStake + amount
	if newStake > v.config.MaxStake {
		return fmt.Errorf("stake would exceed maximum: %d > %d", newStake, v.config.MaxStake)
	}

	v.delegatedStake = newStake
	v.updatePower()
	return nil
}

// UndelegateStake removes stake from the validator
func (v *Validator) UndelegateStake(amount uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if amount > v.delegatedStake {
		return fmt.Errorf("insufficient stake: %d > %d", amount, v.delegatedStake)
	}

	newStake := v.delegatedStake - amount
	if newStake < v.config.MinStake && v.status == StatusActive {
		return fmt.Errorf("stake would fall below minimum: %d < %d", newStake, v.config.MinStake)
	}

	v.delegatedStake = newStake
	v.updatePower()
	return nil
}

// Internal methods

func (v *Validator) jail() error {
	if v.status == StatusJailed {
		return nil
	}

	v.status = StatusJailing
	v.power = 0

	// Schedule unjailing
	time.AfterFunc(v.config.JailDuration, func() {
		v.mu.Lock()
		defer v.mu.Unlock()

		if v.status == StatusJailing {
			v.status = StatusActive
			v.updatePower()
		}
	})

	return nil
}

func (v *Validator) slash() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.status = StatusSlashed
	slashAmount := v.delegatedStake / 2 // 50% slash
	v.delegatedStake -= slashAmount
	v.power = 0
	v.stats.slashingEvents++

	return nil
}

func (v *Validator) updatePower() {
	// Power is proportional to stake and reputation
	v.power = v.delegatedStake * uint64(v.reputation) / 100
}

func (v *Validator) signBlock(block *core.Block) error {
	blockHash := block.Hash()
	signature := ed25519.Sign(v.privateKey, blockHash[:])
	block.Signature = signature
	return nil
}

func (v *Validator) verifyBlockSignature(block *core.Block) error {
	blockHash := block.Hash()
	return v.verifySignature(blockHash[:], block.Signature)
}

func (v *Validator) verifySignature(message, signature []byte) error {
	if !ed25519.Verify(v.publicKey, message, signature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (v *Validator) verifyTransactions(block *core.Block) error {
	for _, tx := range block.Transactions {
		if err := tx.Verify(); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}
	return nil
}

// Background loops

func (v *Validator) validationLoop(ctx context.Context) {
	ticker := time.NewTicker(v.config.BlockTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.checkMissedBlocks()
		}
	}
}

func (v *Validator) reputationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.decayReputation()
		}
	}
}

func (v *Validator) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.updateStats()
		}
	}
}

func (v *Validator) checkMissedBlocks() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if time.Since(v.stats.lastValidatedBlock) > v.config.BlockTimeout {
		v.stats.missedBlocks++
		if v.stats.missedBlocks > v.config.MaxMissedBlocks {
			v.jail()
		}
	}
}

func (v *Validator) decayReputation() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.reputation > 0 {
		decayAmount := uint32(float64(v.reputation) * v.config.ReputationDecay)
		if decayAmount > 0 {
			v.reputation -= decayAmount
		}
	}
}

func (v *Validator) updateStats() {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.stats.uptime = time.Since(v.stats.startTime)
}

// Helper functions

func newValidatorStats() *ValidatorStats {
	return &ValidatorStats{
		startTime: time.Now(),
	}
}

// GetStatus returns the current validator status and statistics
func (v *Validator) GetStatus() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return map[string]interface{}{
		"address":         v.address.String(),
		"publicKey":       hex.EncodeToString(v.publicKey),
		"status":          v.status,
		"power":           v.power,
		"reputation":      v.reputation,
		"delegatedStake":  v.delegatedStake,
		"totalBlocks":     v.stats.totalBlocks,
		"proposedBlocks":  v.stats.proposedBlocks,
		"validatedBlocks": v.stats.validatedBlocks,
		"missedBlocks":    v.stats.missedBlocks,
		"slashingEvents":  v.stats.slashingEvents,
		"uptime":          v.stats.uptime.String(),
		"lastProposed":    v.stats.lastProposedBlock,
		"lastValidated":   v.stats.lastValidatedBlock,
	}
}

// GetReputation returns the current reputation score
func (v *Validator) GetReputation() uint32 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.reputation
}

// GetAddress returns the validator's address
func (v *Validator) GetAddress() types.Address {
	return v.address
}

// GetPublicKey returns the validator's public key
func (v *Validator) GetPublicKey() []byte {
	return v.publicKey
}
