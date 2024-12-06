// Package consensus implements the reputation scoring system for ATLYS
package consensus

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/atlys/pkg/core"
	"github.com/atlys/pkg/types"
)

// ReputationScorer manages validator reputation scores
type ReputationScorer struct {
	mu           sync.RWMutex
	scores       map[types.Address]*ValidatorScore
	history      map[types.Address]*ScoreHistory
	config       *ReputationConfig
	epochManager *EpochManager
}

// ValidatorScore represents a validator's current reputation metrics
type ValidatorScore struct {
	CurrentScore    uint32    // Current reputation score (0-100)
	BaseScore       uint32    // Base score without penalties
	PenaltyScore    uint32    // Accumulated penalties
	LastUpdate      time.Time // Last score update timestamp
	ConsecutiveHits uint32    // Consecutive successful validations
	StakeWeight     float64   // Weight based on staked amount
}

// ScoreHistory tracks historical reputation data
type ScoreHistory struct {
	Scores      []uint32    // Historical scores
	Updates     []time.Time // Update timestamps
	SlashEvents []SlashEvent
	MaxEntries  uint32
}

// SlashEvent records details of a slashing event
type SlashEvent struct {
	Timestamp   time.Time
	Reason      string
	Amount      uint32
	BlockHeight uint64
}

// ReputationConfig contains configuration parameters for the reputation system
type ReputationConfig struct {
	InitialScore      uint32
	MinScore          uint32
	MaxScore          uint32
	DecayRate         float64
	DecayInterval     time.Duration
	UpdateInterval    time.Duration
	BonusMultiplier   float64
	PenaltyMultiplier float64
	SlashingThreshold uint32
	RecoveryRate      float64
	HistorySize       uint32
	ConsensusWeight   float64
	StakeWeight       float64
	UptimeWeight      float64
}

// EpochManager handles epoch-based score calculations
type EpochManager struct {
	currentEpoch  uint64
	epochInterval time.Duration
	startTime     time.Time
}

// NewReputationScorer creates a new instance of ReputationScorer
func NewReputationScorer(config *ReputationConfig) *ReputationScorer {
	return &ReputationScorer{
		scores:  make(map[types.Address]*ValidatorScore),
		history: make(map[types.Address]*ScoreHistory),
		config:  config,
		epochManager: &EpochManager{
			epochInterval: time.Hour * 24, // 1 day epochs
			startTime:     time.Now(),
		},
	}
}

// RegisterValidator initializes reputation tracking for a new validator
func (rs *ReputationScorer) RegisterValidator(address types.Address, stake uint64) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if _, exists := rs.scores[address]; exists {
		return fmt.Errorf("validator already registered")
	}

	// Initialize score
	rs.scores[address] = &ValidatorScore{
		CurrentScore: rs.config.InitialScore,
		BaseScore:    rs.config.InitialScore,
		LastUpdate:   time.Now(),
		StakeWeight:  calculateStakeWeight(stake),
	}

	// Initialize history
	rs.history[address] = &ScoreHistory{
		MaxEntries: rs.config.HistorySize,
	}

	return nil
}

// UpdateScore updates a validator's reputation score based on performance
func (rs *ReputationScorer) UpdateScore(address types.Address, success bool, metrics *ValidationMetrics) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	score, exists := rs.scores[address]
	if !exists {
		return fmt.Errorf("validator not registered")
	}

	// Calculate score components
	consensusScore := rs.calculateConsensusScore(success, metrics)
	stakeScore := rs.calculateStakeScore(score.StakeWeight)
	uptimeScore := rs.calculateUptimeScore(metrics)

	// Compute weighted score
	newScore := uint32(
		float64(consensusScore)*rs.config.ConsensusWeight +
			float64(stakeScore)*rs.config.StakeWeight +
			float64(uptimeScore)*rs.config.UptimeWeight,
	)

	// Apply bounds
	newScore = boundScore(newScore, rs.config.MinScore, rs.config.MaxScore)

	// Update score
	score.CurrentScore = newScore
	score.LastUpdate = time.Now()

	// Update history
	rs.updateHistory(address, newScore)

	return nil
}

// SlashValidator applies a slashing penalty to a validator
func (rs *ReputationScorer) SlashValidator(address types.Address, reason string, blockHeight uint64) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	score, exists := rs.scores[address]
	if !exists {
		return fmt.Errorf("validator not registered")
	}

	// Calculate slash amount based on severity
	slashAmount := rs.calculateSlashAmount(reason, score.CurrentScore)

	// Apply penalty
	score.PenaltyScore += slashAmount
	score.CurrentScore = boundScore(
		score.CurrentScore-slashAmount,
		rs.config.MinScore,
		rs.config.MaxScore,
	)

	// Record slash event
	history := rs.history[address]
	history.SlashEvents = append(history.SlashEvents, SlashEvent{
		Timestamp:   time.Now(),
		Reason:      reason,
		Amount:      slashAmount,
		BlockHeight: blockHeight,
	})

	return nil
}

// RecoverScore allows gradual score recovery after penalties
func (rs *ReputationScorer) RecoverScore(address types.Address) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	score, exists := rs.scores[address]
	if !exists {
		return fmt.Errorf("validator not registered")
	}

	if score.PenaltyScore > 0 {
		// Calculate recovery amount
		recoveryAmount := uint32(float64(score.PenaltyScore) * rs.config.RecoveryRate)
		if recoveryAmount > score.PenaltyScore {
			recoveryAmount = score.PenaltyScore
		}

		// Apply recovery
		score.PenaltyScore -= recoveryAmount
		score.CurrentScore = boundScore(
			score.CurrentScore+recoveryAmount,
			rs.config.MinScore,
			rs.config.MaxScore,
		)
	}

	return nil
}

// GetScore returns a validator's current reputation score
func (rs *ReputationScorer) GetScore(address types.Address) (uint32, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	score, exists := rs.scores[address]
	if !exists {
		return 0, fmt.Errorf("validator not registered")
	}

	return score.CurrentScore, nil
}

// GetHistory returns a validator's reputation history
func (rs *ReputationScorer) GetHistory(address types.Address) (*ScoreHistory, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	history, exists := rs.history[address]
	if !exists {
		return nil, fmt.Errorf("validator not registered")
	}

	return history, nil
}

// Internal helper methods

func (rs *ReputationScorer) calculateConsensusScore(success bool, metrics *ValidationMetrics) uint32 {
	if success {
		return uint32(float64(metrics.ConsensusParticipation) * rs.config.BonusMultiplier)
	}
	return uint32(float64(metrics.ConsensusParticipation) * rs.config.PenaltyMultiplier)
}

func (rs *ReputationScorer) calculateStakeScore(stakeWeight float64) uint32 {
	return uint32(float64(rs.config.MaxScore) * stakeWeight)
}

func (rs *ReputationScorer) calculateUptimeScore(metrics *ValidationMetrics) uint32 {
	return uint32(float64(rs.config.MaxScore) * metrics.Uptime)
}

func (rs *ReputationScorer) calculateSlashAmount(reason string, currentScore uint32) uint32 {
	// Slash amount varies by reason
	switch reason {
	case "double_sign":
		return currentScore / 2 // 50% penalty
	case "unavailable":
		return currentScore / 4 // 25% penalty
	case "invalid_validation":
		return currentScore / 5 // 20% penalty
	default:
		return currentScore / 10 // 10% penalty
	}
}

func (rs *ReputationScorer) updateHistory(address types.Address, newScore uint32) {
	history := rs.history[address]

	// Add new score
	history.Scores = append(history.Scores, newScore)
	history.Updates = append(history.Updates, time.Now())

	// Maintain maximum history size
	if uint32(len(history.Scores)) > history.MaxEntries {
		history.Scores = history.Scores[1:]
		history.Updates = history.Updates[1:]
	}
}

// Helper functions

func calculateStakeWeight(stake uint64) float64 {
	// Logarithmic stake weight calculation
	return math.Log1p(float64(stake)) / math.Log1p(float64(math.MaxUint64))
}

func boundScore(score, min, max uint32) uint32 {
	if score < min {
		return min
	}
	if score > max {
		return max
	}
	return score
}

// ValidationMetrics contains metrics used for score calculation
type ValidationMetrics struct {
	ConsensusParticipation float64 // 0.0 to 1.0
	Uptime                 float64 // 0.0 to 1.0
	ResponseTime           time.Duration
	ProposedBlocks         uint64
	ValidatedBlocks        uint64
}

// Epoch-based calculations

func (rs *ReputationScorer) StartNewEpoch() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.epochManager.currentEpoch++

	// Perform epoch-based score adjustments
	for _, score := range rs.scores {
		// Apply score decay
		decayAmount := uint32(float64(score.CurrentScore) * rs.config.DecayRate)
		score.CurrentScore = boundScore(
			score.CurrentScore-decayAmount,
			rs.config.MinScore,
			rs.config.MaxScore,
		)
	}
}

// GetEpochStats returns reputation statistics for the current epoch
func (rs *ReputationScorer) GetEpochStats() map[string]interface{} {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	stats := make(map[string]interface{})
	var totalScore uint32
	var activeValidators uint32

	for _, score := range rs.scores {
		totalScore += score.CurrentScore
		if score.CurrentScore > 0 {
			activeValidators++
		}
	}

	stats["epoch"] = rs.epochManager.currentEpoch
	stats["average_score"] = totalScore / activeValidators
	stats["active_validators"] = activeValidators
	stats["epoch_start"] = rs.epochManager.startTime.Add(
		time.Duration(rs.epochManager.currentEpoch) * rs.epochManager.epochInterval,
	)

	return stats
}
