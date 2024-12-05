// Package bridge implements state management for the ATLYS protocol
package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/atlys/pkg/core"
	"github.com/atlys/pkg/types"
)

// StateManager handles cross-chain state synchronization and verification
type StateManager struct {
	mu            sync.RWMutex
	chainStates   map[string]*ChainState
	stateRoots    map[string]types.Hash
	proofRegistry map[types.Hash]*StateProof
	config        *StateConfig
}

// ChainState represents the current state of a blockchain
type ChainState struct {
	ChainID           string
	LastHeight        uint64
	LastStateRoot     types.Hash
	LastUpdateTime    time.Time
	PendingUpdates    map[uint64]*StateUpdate
	CrossChainAnchors map[string]uint64 // Maps chain ID to last anchored height
}

// StateUpdate represents a pending state update
type StateUpdate struct {
	Height     uint64
	StateRoot  types.Hash
	Timestamp  time.Time
	Validators []types.ValidatorAddress
	Signatures map[types.ValidatorAddress][]byte
}

// StateProof contains proof data for cross-chain verification
type StateProof struct {
	SourceChain      string
	DestinationChain string
	Height           uint64
	StateRoot        types.Hash
	ProofData        []byte
	Timestamp        time.Time
	ValidatorSigs    map[types.ValidatorAddress][]byte
}

// StateConfig contains configuration parameters for state management
type StateConfig struct {
	UpdateInterval     time.Duration
	MaxPendingUpdates uint64
	ProofExpiration   time.Duration
	MinValidators     uint64
}

// NewStateManager creates a new instance of StateManager
func NewStateManager(config *StateConfig) *StateManager {
	return &StateManager{
		chainStates:   make(map[string]*ChainState),
		stateRoots:    make(map[string]types.Hash),
		proofRegistry: make(map[types.Hash]*StateProof),
		config:        config,
	}
}

// RegisterChain initializes state tracking for a new chain
func (sm *StateManager) RegisterChain(chainID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.chainStates[chainID]; exists {
		return fmt.Errorf("chain %s already registered", chainID)
	}

	sm.chainStates[chainID] = &ChainState{
		ChainID:           chainID,
		PendingUpdates:    make(map[uint64]*StateUpdate),
		CrossChainAnchors: make(map[string]uint64),
		LastUpdateTime:    time.Now(),
	}

	return nil
}

// UpdateChainState processes a new state update from a chain
func (sm *StateManager) UpdateChainState(chainID string, height uint64, stateRoot types.Hash, validators []types.ValidatorAddress) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	state, exists := sm.chainStates[chainID]
	if !exists {
		return fmt.Errorf("chain %s not registered", chainID)
	}

	// Verify height is greater than last recorded height
	if height <= state.LastHeight {
		return fmt.Errorf("invalid height: %d <= %d", height, state.LastHeight)
	}

	// Create new state update
	update := &StateUpdate{
		Height:     height,
		StateRoot:  stateRoot,
		Timestamp:  time.Now(),
		Validators: validators,
		Signatures: make(map[types.ValidatorAddress][]byte),
	}

	// Add to pending updates
	if uint64(len(state.PendingUpdates)) >= sm.config.MaxPendingUpdates {
		return fmt.Errorf("maximum pending updates reached for chain %s", chainID)
	}

	state.PendingUpdates[height] = update
	return nil
}

// ValidateStateUpdate verifies a state update with validator signatures
func (sm *StateManager) ValidateStateUpdate(chainID string, height uint64, signature []byte, validator types.ValidatorAddress) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	state, exists := sm.chainStates[chainID]
	if !exists {
		return fmt.Errorf("chain %s not registered", chainID)
	}

	update, exists := state.PendingUpdates[height]
	if !exists {
		return fmt.Errorf("no pending update for height %d", height)
	}

	// Add validator signature
	update.Signatures[validator] = signature

	// Check if we have enough signatures
	if uint64(len(update.Signatures)) >= sm.config.MinValidators {
		// Finalize state update
		if err := sm.finalizeStateUpdate(chainID, height); err != nil {
			return fmt.Errorf("failed to finalize state update: %w", err)
		}
	}

	return nil
}

// GenerateStateProof creates a proof for cross-chain verification
func (sm *StateManager) GenerateStateProof(sourceChain, destChain string, height uint64) (*StateProof, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sourceState, exists := sm.chainStates[sourceChain]
	if !exists {
		return nil, fmt.Errorf("source chain %s not registered", sourceChain)
	}

	if height > sourceState.LastHeight {
		return nil, fmt.Errorf("height %d not yet finalized", height)
	}

	// Generate proof data
	proofData, err := sm.generateProofData(sourceChain, height)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof data: %w", err)
	}

	proof := &StateProof{
		SourceChain:      sourceChain,
		DestinationChain: destChain,
		Height:           height,
		StateRoot:        sourceState.LastStateRoot,
		ProofData:        proofData,
		Timestamp:        time.Now(),
		ValidatorSigs:    make(map[types.ValidatorAddress][]byte),
	}

	proofHash := sm.calculateProofHash(proof)
	sm.proofRegistry[proofHash] = proof

	return proof, nil
}

// VerifyStateProof verifies a cross-chain state proof
func (sm *StateManager) VerifyStateProof(proof *StateProof) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Verify proof hasn't expired
	if time.Since(proof.Timestamp) > sm.config.ProofExpiration {
		return fmt.Errorf("proof has expired")
	}

	// Verify source chain state
	sourceState, exists := sm.chainStates[proof.SourceChain]
	if !exists {
		return fmt.Errorf("source chain %s not registered", proof.SourceChain)
	}

	if proof.Height > sourceState.LastHeight {
		return fmt.Errorf("proof height exceeds chain height")
	}

	// Verify proof data
	if err := sm.verifyProofData(proof); err != nil {
		return fmt.Errorf("invalid proof data: %w", err)
	}

	// Verify validator signatures
	if uint64(len(proof.ValidatorSigs)) < sm.config.MinValidators {
		return fmt.Errorf("insufficient validator signatures")
	}

	return nil
}

// Internal helper methods

func (sm *StateManager) finalizeStateUpdate(chainID string, height uint64) error {
	state := sm.chainStates[chainID]
	update := state.PendingUpdates[height]

	// Update chain state
	state.LastHeight = height
	state.LastStateRoot = update.StateRoot
	state.LastUpdateTime = time.Now()

	// Clean up pending updates
	delete(state.PendingUpdates, height)

	// Update state roots
	sm.stateRoots[chainID] = update.StateRoot

	return nil
}

func (sm *StateManager) generateProofData(chainID string, height uint64) ([]byte, error) {
	// Implementation depends on specific chain's state proof mechanism
	return nil, nil
}

func (sm *StateManager) verifyProofData(proof *StateProof) error {
	// Implementation depends on specific chain's state proof verification
	return nil
}

func (sm *StateManager) calculateProofHash(proof *StateProof) types.Hash {
	data := struct {
		SourceChain string
		Height      uint64
		StateRoot   types.Hash
		Timestamp   time.Time
	}{
		SourceChain: proof.SourceChain,
		Height:      proof.Height,
		StateRoot:   proof.StateRoot,
		Timestamp:   proof.Timestamp,
	}

	bytes, _ := json.Marshal(data)
	hash := sha256.Sum256(bytes)
	return hash
}

// GetChainState returns the current state of a chain
func (sm *StateManager) GetChainState(chainID string) (*ChainState, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	state, exists := sm.chainStates[chainID]
	if !exists {
		return nil, fmt.Errorf("chain %s not registered", chainID)
	}

	return state, nil
}

// UpdateCrossChainAnchor updates the last anchored height for cross-chain references
func (sm *StateManager) UpdateCrossChainAnchor(sourceChain, targetChain string, height uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sourceState, exists := sm.chainStates[sourceChain]
	if !exists {
		return fmt.Errorf("source chain %s not registered", sourceChain)
	}

	if height > sourceState.LastHeight {
		return fmt.Errorf("height %d exceeds current chain height", height)
	}

	sourceState.CrossChainAnchors[targetChain] = height
	return nil
}

// GetLastAnchoredHeight returns the last anchored height between two chains
func (sm *StateManager) GetLastAnchoredHeight(sourceChain, targetChain string) (uint64, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sourceState, exists := sm.chainStates[sourceChain]
	if !exists {
		return 0, fmt.Errorf("source chain %s not registered", sourceChain)
	}

	height, exists := sourceState.CrossChainAnchors[targetChain]
	if !exists {
		return 0, fmt.Errorf("no anchor exists for target chain %s", targetChain)
	}

	return height, nil
}