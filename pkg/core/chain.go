package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/atlys/pkg/types"
	"github.com/atlys/pkg/store"
)

type Chain struct {
	mu sync.RWMutex

	ID               string
	blocks           []*Block
	pendingTxs       []types.Transaction
	height           uint64
	lastBlockTime    time.Time
	validators       []types.ValidatorAddress
	store           store.BlockStore
	txPool          *TxPool
	consensusParams  ConsensusParams
}

type ConsensusParams struct {
	BlockInterval    time.Duration
	MaxBlockSize     uint64
	MaxTxsPerBlock   uint64
	ValidatorQuorum  float64
}

type TxPool struct {
	mu      sync.RWMutex
	pending map[types.Hash]types.Transaction
	maxSize uint64
}

func NewChain(id string, store store.BlockStore, params ConsensusParams) *Chain {
	return &Chain{
		ID:              id,
		store:          store,
		txPool:         NewTxPool(1000), // Configure pool size
		consensusParams: params,
	}
}

func (c *Chain) Start(ctx context.Context) error {
	// Load chain state from store
	height, err := c.store.GetHeight()
	if err != nil {
		return fmt.Errorf("failed to get chain height: %w", err)
	}

	c.height = height
	if height > 0 {
		lastBlock, err := c.store.GetBlock(height)
		if err != nil {
			return fmt.Errorf("failed to get last block: %w", err)
		}
		c.lastBlockTime = lastBlock.Timestamp
	}

	go c.blockProduction(ctx)
	return nil
}

func (c *Chain) AddBlock(block *Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.validateBlock(block); err != nil {
		return fmt.Errorf("invalid block: %w", err)
	}

	if err := c.store.SaveBlock(block); err != nil {
		return fmt.Errorf("failed to save block: %w", err)
	}

	c.height = block.Height
	c.lastBlockTime = block.Timestamp
	c.cleanTxPool(block.Transactions)

	return nil
}

func (c *Chain) AddTransaction(tx types.Transaction) error {
	if err := tx.Verify(); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}

	return c.txPool.Add(tx)
}

func (c *Chain) GetBlock(height uint64) (*Block, error) {
	return c.store.GetBlock(height)
}

func (c *Chain) GetTransaction(hash types.Hash) (*types.Transaction, error) {
	return c.store.GetTransaction(hash)
}

func (c *Chain) GetHeight() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.height
}

func (c *Chain) validateBlock(block *Block) error {
	// Basic validation
	if block.Height != c.height+1 {
		return fmt.Errorf("invalid block height: expected %d, got %d", c.height+1, block.Height)
	}

	if block.PreviousHash != c.blocks[len(c.blocks)-1].Hash {
		return fmt.Errorf("invalid previous hash")
	}

	if block.Timestamp.Before(c.lastBlockTime) {
		return fmt.Errorf("invalid block timestamp")
	}

	// Validate block size
	if block.Size() > c.consensusParams.MaxBlockSize {
		return fmt.Errorf("block size exceeds maximum")
	}

	// Validate transactions
	for _, tx := range block.Transactions {
		if err := tx.Verify(); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}

	// Validate validator signatures
	if err := block.Verify(); err != nil {
		return fmt.Errorf("block verification failed: %w", err)
	}

	return nil
}

func (c *Chain) blockProduction(ctx context.Context) {
	ticker := time.NewTicker(c.consensusParams.BlockInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.produceBlock()
		}
	}
}

func (c *Chain) produceBlock() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get transactions from pool
	transactions := c.txPool.GetPending(c.consensusParams.MaxTxsPerBlock)
	if len(transactions) == 0 {
		return nil // Skip empty blocks
	}

	// Create new block
	block := NewBlock(
		c.height+1,
		c.blocks[len(c.blocks)-1].Hash,
		transactions,
	)

	// Add validator set
	block.ValidatorSet = c.validators

	// Sign block if we're a validator
	// TODO: Implement validator logic

	// Add block to chain
	if err := c.AddBlock(block); err != nil {
		return fmt.Errorf("failed to add block: %w", err)
	}

	return nil
}

func (c *Chain) cleanTxPool(transactions []types.Transaction) {
	for _, tx := range transactions {
		c.txPool.Remove(tx.Hash())
	}
}

// TxPool methods

func NewTxPool(maxSize uint64) *TxPool {
	return &TxPool{
		pending: make(map[types.Hash]types.Transaction),
		maxSize: maxSize,
	}
}

func (p *TxPool) Add(tx types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if uint64(len(p.pending)) >= p.maxSize {
		return fmt.Errorf("transaction pool is full")
	}

	hash := tx.Hash()
	p.pending[hash] = tx
	return nil
}

func (p *TxPool) Remove(hash types.Hash) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, hash)
}

func (p *TxPool) GetPending(limit uint64) []types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var txs []types.Transaction
	for _, tx := range p.pending {
		if uint64(len(txs)) >= limit {
			break
		}
		txs = append(txs, tx)
	}
	return txs
}