// Package bridge implements asset management for the ATLYS protocol
package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/atlys/pkg/core"
	"github.com/atlys/pkg/types"
)

// AssetManager handles cross-chain asset transfers and management
type AssetManager struct {
	mu            sync.RWMutex
	assets        map[string]*Asset
	lockedAssets  map[types.Hash]*LockedAsset
	assetPairs    map[string]map[string]*AssetPair
	config        *AssetConfig
}

// Asset represents a registered asset across chains
type Asset struct {
	Symbol          string
	Name            string
	Decimals        uint8
	TotalSupply     uint64
	NativeChain     string
	SupportedChains map[string]*AssetInfo
	LastUpdate      time.Time
}

// AssetInfo contains chain-specific asset information
type AssetInfo struct {
	ContractAddress string
	TotalLocked    uint64
	TotalMinted    uint64
	LastHeight     uint64
}

// LockedAsset represents assets locked for cross-chain transfer
type LockedAsset struct {
	TxHash          types.Hash
	SourceChain     string
	DestChain       string
	Asset           string
	Amount          uint64
	Owner           types.Address
	LockTime        time.Time
	ExpirationTime  time.Time
	Status          LockStatus
}

// AssetPair represents a cross-chain asset pair configuration
type AssetPair struct {
	BaseAsset    string
	QuoteAsset   string
	SourceChain  string
	DestChain    string
	ExchangeRate uint64 // Base rate multiplied by 10^8
	UpdateTime   time.Time
}

// LockStatus represents the current status of locked assets
type LockStatus int

const (
	StatusLocked LockStatus = iota
	StatusReleased
	StatusTransferred
	StatusExpired
)

// AssetConfig contains configuration parameters for asset management
type AssetConfig struct {
	LockTimeout      time.Duration
	MinLockAmount    uint64
	MaxLockAmount    uint64
	RateUpdateInterval time.Duration
}

// NewAssetManager creates a new instance of AssetManager
func NewAssetManager(config *AssetConfig) *AssetManager {
	return &AssetManager{
		assets:       make(map[string]*Asset),
		lockedAssets: make(map[types.Hash]*LockedAsset),
		assetPairs:   make(map[string]map[string]*AssetPair),
		config:       config,
	}
}

// RegisterAsset adds a new asset to the registry
func (am *AssetManager) RegisterAsset(asset *Asset) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.assets[asset.Symbol]; exists {
		return fmt.Errorf("asset %s already registered", asset.Symbol)
	}

	if asset.SupportedChains == nil {
		asset.SupportedChains = make(map[string]*AssetInfo)
	}

	asset.LastUpdate = time.Now()
	am.assets[asset.Symbol] = asset

	return nil
}

// RegisterAssetPair creates a new cross-chain asset pair
func (am *AssetManager) RegisterAssetPair(pair *AssetPair) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Verify both assets exist
	if _, exists := am.assets[pair.BaseAsset]; !exists {
		return fmt.Errorf("base asset %s not registered", pair.BaseAsset)
	}
	if _, exists := am.assets[pair.QuoteAsset]; !exists {
		return fmt.Errorf("quote asset %s not registered", pair.QuoteAsset)
	}

	// Initialize chain map if needed
	if _, exists := am.assetPairs[pair.SourceChain]; !exists {
		am.assetPairs[pair.SourceChain] = make(map[string]*AssetPair)
	}

	pairKey := fmt.Sprintf("%s_%s", pair.BaseAsset, pair.QuoteAsset)
	am.assetPairs[pair.SourceChain][pairKey] = pair

	return nil
}

// LockAssets locks assets for cross-chain transfer
func (am *AssetManager) LockAssets(ctx context.Context, tx *types.Transaction) (*LockedAsset, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Verify transaction
	if err := am.verifyTransferTransaction(tx); err != nil {
		return nil, err
	}

	// Create locked asset record
	locked := &LockedAsset{
		TxHash:         tx.Hash(),
		SourceChain:    tx.SourceChain,
		DestChain:      tx.DestinationChain,
		Asset:          tx.AssetSymbol,
		Amount:         tx.Amount,
		Owner:          tx.From,
		LockTime:       time.Now(),
		ExpirationTime: time.Now().Add(am.config.LockTimeout),
		Status:         StatusLocked,
	}

	// Store locked asset
	am.lockedAssets[tx.Hash()] = locked

	// Update asset info
	if err := am.updateAssetInfo(tx.AssetSymbol, tx.SourceChain, tx.Amount, true); err != nil {
		return nil, err
	}

	return locked, nil
}

// ReleaseAssets releases locked assets
func (am *AssetManager) ReleaseAssets(txHash types.Hash) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	locked, exists := am.lockedAssets[txHash]
	if !exists {
		return fmt.Errorf("locked assets not found for tx %s", txHash.String())
	}

	if locked.Status != StatusLocked {
		return fmt.Errorf("assets already released or transferred")
	}

	// Update asset info
	if err := am.updateAssetInfo(locked.Asset, locked.SourceChain, locked.Amount, false); err != nil {
		return err
	}

	locked.Status = StatusReleased
	return nil
}

// TransferAssets completes a cross-chain asset transfer
func (am *AssetManager) TransferAssets(ctx context.Context, txHash types.Hash) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	locked, exists := am.lockedAssets[txHash]
	if !exists {
		return fmt.Errorf("locked assets not found for tx %s", txHash.String())
	}

	if locked.Status != StatusLocked {
		return fmt.Errorf("invalid asset status for transfer")
	}

	// Verify asset support on destination chain
	asset := am.assets[locked.Asset]
	if _, exists := asset.SupportedChains[locked.DestChain]; !exists {
		return fmt.Errorf("asset %s not supported on chain %s", locked.Asset, locked.DestChain)
	}

	// Update destination chain asset info
	destInfo := asset.SupportedChains[locked.DestChain]
	destInfo.TotalMinted += locked.Amount
	destInfo.LastHeight += 1

	locked.Status = StatusTransferred
	return nil
}

// GetLockedAssets returns information about locked assets
func (am *AssetManager) GetLockedAssets(txHash types.Hash) (*LockedAsset, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	locked, exists := am.lockedAssets[txHash]
	if !exists {
		return nil, fmt.Errorf("locked assets not found")
	}

	return locked, nil
}

// GetAssetInfo returns information about a registered asset
func (am *AssetManager) GetAssetInfo(symbol string) (*Asset, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	asset, exists := am.assets[symbol]
	if !exists {
		return nil, fmt.Errorf("asset %s not found", symbol)
	}

	return asset, nil
}

// Internal helper methods

func (am *AssetManager) verifyTransferTransaction(tx *types.Transaction) error {
	// Verify asset exists
	asset, exists := am.assets[tx.AssetSymbol]
	if !exists {
		return fmt.Errorf("asset %s not registered", tx.AssetSymbol)
	}

	// Verify chains support the asset
	if _, exists := asset.SupportedChains[tx.SourceChain]; !exists {
		return fmt.Errorf("asset %s not supported on source chain %s", tx.AssetSymbol, tx.SourceChain)
	}
	if _, exists := asset.SupportedChains[tx.DestinationChain]; !exists {
		return fmt.Errorf("asset %s not supported on destination chain %s", tx.AssetSymbol, tx.DestinationChain)
	}

	// Verify amount
	if tx.Amount < am.config.MinLockAmount || tx.Amount > am.config.MaxLockAmount {
		return fmt.Errorf("invalid transfer amount")
	}

	return nil
}

func (am *AssetManager) updateAssetInfo(symbol, chainID string, amount uint64, isLock bool) error {
	asset := am.assets[symbol]
	info := asset.SupportedChains[chainID]

	if isLock {
		info.TotalLocked += amount
	} else {
		if info.TotalLocked < amount {
			return fmt.Errorf("insufficient locked amount")
		}
		info.TotalLocked -= amount
	}

	info.LastHeight += 1
	return nil
}

// CleanExpiredLocks removes expired locked assets
func (am *AssetManager) CleanExpiredLocks() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	for hash, locked := range am.lockedAssets {
		if locked.Status == StatusLocked && now.After(locked.ExpirationTime) {
			locked.Status = StatusExpired
			// Release the locked amount
			am.updateAssetInfo(locked.Asset, locked.SourceChain, locked.Amount, false)
		}
	}
}

// UpdateExchangeRate updates the exchange rate for an asset pair
func (am *AssetManager) UpdateExchangeRate(sourceChain string, baseAsset string, quoteAsset string, newRate uint64) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	chainPairs, exists := am.assetPairs[sourceChain]
	if !exists {
		return fmt.Errorf("no pairs registered for chain %s", sourceChain)
	}

	pairKey := fmt.Sprintf("%s_%s", baseAsset, quoteAsset)
	pair, exists := chainPairs[pairKey]
	if !exists {
		return fmt.Errorf("pair %s not found", pairKey)
	}

	pair.ExchangeRate = newRate
	pair.UpdateTime = time.Now()

	return nil
}

// GetExchangeRate returns the current exchange rate for an asset pair
func (am *AssetManager) GetExchangeRate(sourceChain string, baseAsset string, quoteAsset string) (uint64, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	chainPairs, exists := am.assetPairs[sourceChain]
	if !exists {
		return 0, fmt.Errorf("no pairs registered for chain %s", sourceChain)
	}

	pairKey := fmt.Sprintf("%s_%s", baseAsset, quoteAsset)
	pair, exists := chainPairs[pairKey]
	if !exists {
		return 0, fmt.Errorf("pair %s not found", pairKey)
	}

	// Check if rate is stale
	if time.Since(pair.UpdateTime) > am.config.RateUpdateInterval {
		return 0, fmt.Errorf("exchange rate is stale")
	}

	return pair.ExchangeRate, nil
}