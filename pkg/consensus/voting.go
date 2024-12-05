// Package consensus implements the voting mechanism for ATLYS
package consensus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/atlys/pkg/core"
	"github.com/atlys/pkg/types"
)

// VoteType represents different types of votes in the consensus
type VoteType int

const (
	VoteTypePrevote VoteType = iota
	VoteTypePrecommit
	VoteTypeProposal
)

// VoteOption represents voting options
type VoteOption int

const (
	VoteNull VoteOption = iota
	VoteYes
	VoteNo
	VoteAbstain
)

// Vote represents a validator's vote
type Vote struct {
	Type        VoteType
	Height      uint64
	Round       uint32
	BlockHash   types.Hash
	Timestamp   time.Time
	ValidatorID types.Address
	Signature   []byte
	Option      VoteOption
}

// VoteSet tracks votes for a specific height and round
type VoteSet struct {
	mu           sync.RWMutex
	height       uint64
	round        uint32
	voteType     VoteType
	votes        map[types.Address]*Vote
	votedPower   uint64
	totalPower   uint64
	maj23Hash    *types.Hash // 2/3 majority hash
	commits      map[types.Hash]*core.Block
	config       *VotingConfig
}

// VotingManager handles the voting process
type VotingManager struct {
	mu              sync.RWMutex
	currentHeight   uint64
	currentRound    uint32
	voteSets        map[uint64]map[uint32]*VoteSet
	validators      *ValidatorSet
	config          *VotingConfig
	timeoutConfig   *TimeoutConfig
}

// VotingConfig contains configuration for voting
type VotingConfig struct {
	VotingPeriod        time.Duration
	ProposalTimeout     time.Duration
	PrevoteTimeout      time.Duration
	PrecommitTimeout    time.Duration
	MinVotingPower      uint64
	MaxRounds           uint32
	RequiredMajority    float64
}

// TimeoutConfig contains timeout parameters
type TimeoutConfig struct {
	ProposeTimeout    time.Duration
	PrevoteTimeout   time.Duration
	PrecommitTimeout time.Duration
	CommitTimeout    time.Duration
}

// NewVotingManager creates a new instance of VotingManager
func NewVotingManager(validators *ValidatorSet, config *VotingConfig) *VotingManager {
	return &VotingManager{
		currentHeight: 0,
		currentRound: 0,
		voteSets:     make(map[uint64]map[uint32]*VoteSet),
		validators:   validators,
		config:      config,
		timeoutConfig: &TimeoutConfig{
			ProposeTimeout:    time.Second * 30,
			PrevoteTimeout:   time.Second * 30,
			PrecommitTimeout: time.Second * 30,
			CommitTimeout:    time.Second * 30,
		},
	}
}

// StartVoting begins the voting process for a new height
func (vm *VotingManager) StartVoting(ctx context.Context, height uint64) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if height <= vm.currentHeight {
		return fmt.Errorf("invalid height: %d <= %d", height, vm.currentHeight)
	}

	vm.currentHeight = height
	vm.currentRound = 0

	// Initialize vote sets for the new height
	vm.voteSets[height] = make(map[uint32]*VoteSet)
	
	// Start voting rounds
	go vm.runVotingRounds(ctx, height)

	return nil
}

// AddVote adds a vote to the current vote set
func (vm *VotingManager) AddVote(vote *Vote) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Verify vote
	if err := vm.verifyVote(vote); err != nil {
		return fmt.Errorf("invalid vote: %w", err)
	}

	// Get or create vote set
	voteSet, err := vm.getVoteSet(vote.Height, vote.Round, vote.Type)
	if err != nil {
		return err
	}

	// Add vote to set
	if err := voteSet.AddVote(vote); err != nil {
		return err
	}

	// Check for majority
	if voteSet.HasTwoThirdsMajority() {
		vm.processMajorityReached(vote.Height, vote.Round, vote.Type)
	}

	return nil
}

// GetVoteSet returns the vote set for a specific height and round
func (vm *VotingManager) GetVoteSet(height uint64, round uint32, voteType VoteType) (*VoteSet, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return vm.getVoteSet(height, round, voteType)
}

// Internal methods

func (vm *VotingManager) getVoteSet(height uint64, round uint32, voteType VoteType) (*VoteSet, error) {
	rounds, exists := vm.voteSets[height]
	if !exists {
		return nil, fmt.Errorf("no vote sets for height %d", height)
	}

	voteSet, exists := rounds[round]
	if !exists {
		// Create new vote set
		voteSet = &VoteSet{
			height:     height,
			round:      round,
			voteType:   voteType,
			votes:      make(map[types.Address]*Vote),
			commits:    make(map[types.Hash]*core.Block),
			config:     vm.config,
			totalPower: vm.validators.GetTotalPower(),
		}
		rounds[round] = voteSet
	}

	return voteSet, nil
}

func (vm *VotingManager) verifyVote(vote *Vote) error {
	// Verify height and round
	if vote.Height < vm.currentHeight {
		return fmt.Errorf("vote height too low")
	}

	// Verify validator
	validator := vm.validators.GetValidator(vote.ValidatorID)
	if validator == nil {
		return fmt.Errorf("unknown validator")
	}

	// Verify signature
	if err := validator.VerifySignature(vote.BlockHash[:], vote.Signature); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return nil
}

func (vm *VotingManager) processMajorityReached(height uint64, round uint32, voteType VoteType) {
	switch voteType {
	case VoteTypePrevote:
		vm.handlePrevoteMajority(height, round)
	case VoteTypePrecommit:
		vm.handlePrecommitMajority(height, round)
	}
}

// VoteSet methods

func (vs *VoteSet) AddVote(vote *Vote) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Check if validator already voted
	if existing, ok := vs.votes[vote.ValidatorID]; ok {
		if existing.BlockHash == vote.BlockHash {
			return nil // Same vote
		}
		// Remove old vote power
		vs.votedPower -= uint64(vm.validators.GetValidator(vote.ValidatorID).GetPower())
	}

	// Add new vote
	vs.votes[vote.ValidatorID] = vote
	vs.votedPower += uint64(vm.validators.GetValidator(vote.ValidatorID).GetPower())

	// Check for 2/3 majority on specific hash
	if vs.getVotePower(vote.BlockHash) > vs.totalPower*2/3 {
		vs.maj23Hash = &vote.BlockHash
	}

	return nil
}

func (vs *VoteSet) HasTwoThirdsMajority() bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	return vs.maj23Hash != nil
}

func (vs *VoteSet) getVotePower(hash types.Hash) uint64 {
	power := uint64(0)
	for validatorID, vote := range vs.votes {
		if vote.BlockHash == hash {
			power += uint64(vm.validators.GetValidator(validatorID).GetPower())
		}
	}
	return power
}

// Consensus round management

func (vm *VotingManager) runVotingRounds(ctx context.Context, height uint64) {
	for round := uint32(0); round < vm.config.MaxRounds; round++ {
		select {
		case <-ctx.Done():
			return
		default:
			if err := vm.runRound(ctx, height, round); err != nil {
				// Handle round error
				continue
			}
			// Round completed successfully
			return
		}
	}
}

func (vm *VotingManager) runRound(ctx context.Context, height uint64, round uint32) error {
	// Proposal phase
	if err := vm.runProposalPhase(ctx, height, round); err != nil {
		return err
	}

	// Prevote phase
	if err := vm.runPrevotePhase(ctx, height, round); err != nil {
		return err
	}

	// Precommit phase
	if err := vm.runPrecommitPhase(ctx, height, round); err != nil {
		return err
	}

	return nil
}

func (vm *VotingManager) runProposalPhase(ctx context.Context, height uint64, round uint32) error {
	timeout := time.NewTimer(vm.timeoutConfig.ProposeTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout.C:
		return fmt.Errorf("proposal timeout")
	}
}

func (vm *VotingManager) runPrevotePhase(ctx context.Context, height uint64, round uint32) error {
	timeout := time.NewTimer(vm.timeoutConfig.PrevoteTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout.C:
		return fmt.Errorf("prevote timeout")
	}
}

func (vm *VotingManager) runPrecommitPhase(ctx context.Context, height uint64, round uint32) error {
	timeout := time.NewTimer(vm.timeoutConfig.PrecommitTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout.C:
		return fmt.Errorf("precommit timeout")
	}
}

// Helper functions

// CreateVote creates a new signed vote
func (vm *VotingManager) CreateVote(
	voteType VoteType,
	height uint64,
	round uint32,
	blockHash types.Hash,
	option VoteOption,
	validator types.Address,
) (*Vote, error) {
	vote := &Vote{
		Type:        voteType,
		Height:      height,
		Round:       round,
		BlockHash:   blockHash,
		Timestamp:   time.Now(),
		ValidatorID: validator,
		Option:      option,
	}

	// Sign vote
	validatorNode := vm.validators.GetValidator(validator)
	if validatorNode == nil {
		return nil, fmt.Errorf("validator not found")
	}

	signature, err := validatorNode.Sign(blockHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign vote: %w", err)
	}

	vote.Signature = signature
	return vote, nil
}

// GetVotingState returns the current voting state
func (vm *VotingManager) GetVotingState() map[string]interface{} {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return map[string]interface{}{
		"height":        vm.currentHeight,
		"round":         vm.currentRound,
		"total_power":   vm.validators.GetTotalPower(),
		"active_votes":  len(vm.voteSets[vm.currentHeight][vm.currentRound].votes),
		"voting_power":  vm.voteSets[vm.currentHeight][vm.currentRound].votedPower,
	}
}