package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/atlys/pkg/bridge"
	"github.com/atlys/pkg/types"
)

type Config struct {
	ListenAddresses []string
	BootstrapPeers  []string
	MaxPeers        int
	MinPeers        int
}

type P2PNetwork struct {
	host       host.Host
	dht        *dht.IpfsDHT
	validators map[peer.ID]*ValidatorNode
	mu         sync.RWMutex
	protocols  map[protocol.ID]*Protocol
	config     *Config
	ctx        context.Context
	cancel     context.CancelFunc
}

type Protocol struct {
	ID      protocol.ID
	Handler ProtocolHandler
}

type ProtocolHandler interface {
	HandleMessage(ctx context.Context, msg []byte) error
}

type ValidatorNode struct {
	ID       peer.ID
	Address  types.Address
	LastSeen time.Time
	Status   NodeStatus
}

type NodeStatus int

const (
	StatusDisconnected NodeStatus = iota
	StatusConnecting
	StatusConnected
	StatusActive
)

func NewP2PNetwork(cfg *Config) (*P2PNetwork, error) {
	ctx, cancel := context.WithCancel(context.Background())

	host, err := libp2p.New(
		libp2p.ListenAddrStrings(cfg.ListenAddresses...),
		libp2p.EnableRelay(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	dht, err := dht.New(ctx, host)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	return &P2PNetwork{
		host:       host,
		dht:        dht,
		validators: make(map[peer.ID]*ValidatorNode),
		protocols:  make(map[protocol.ID]*Protocol),
		config:     cfg,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (n *P2PNetwork) Start() error {
	if err := n.dht.Bootstrap(n.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	for _, addr := range n.config.BootstrapPeers {
		if err := n.connectToPeer(addr); err != nil {
			return fmt.Errorf("failed to connect to bootstrap peer %s: %w", addr, err)
		}
	}

	go n.discoveryLoop()
	go n.maintenanceLoop()

	return nil
}

func (n *P2PNetwork) Stop() error {
	n.cancel()
	return n.host.Close()
}

func (n *P2PNetwork) RegisterProtocol(id protocol.ID, handler ProtocolHandler) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.protocols[id] = &Protocol{
		ID:      id,
		Handler: handler,
	}

	n.host.SetStreamHandler(id, n.handleStream)
}

func (n *P2PNetwork) Broadcast(protocolID protocol.ID, msg []byte) error {
	n.mu.RLock()
	peers := n.host.Network().Peers()
	n.mu.RUnlock()

	var wg sync.WaitGroup
	errCh := make(chan error, len(peers))

	for _, peer := range peers {
		wg.Add(1)
		go func(p peer.ID) {
			defer wg.Done()
			if err := n.sendMessage(p, protocolID, msg); err != nil {
				errCh <- fmt.Errorf("failed to send to peer %s: %w", p, err)
			}
		}(peer)
	}

	wg.Wait()
	close(errCh)

	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("broadcast errors: %v", errors)
	}
	return nil
}

func (n *P2PNetwork) connectToPeer(addr string) error {
	peerAddr, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	if err := n.host.Connect(n.ctx, *peerAddr); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	return nil
}

func (n *P2PNetwork) handleStream(s protocol.Stream) {
	defer s.Close()

	protocolID := s.Protocol()
	n.mu.RLock()
	protocol, exists := n.protocols[protocolID]
	n.mu.RUnlock()

	if !exists {
		return
	}

	buf := make([]byte, 1024*1024) // 1MB buffer
	for {
		bytes, err := s.Read(buf)
		if err != nil {
			return
		}

		if err := protocol.Handler.HandleMessage(n.ctx, buf[:bytes]); err != nil {
			return
		}
	}
}

func (n *P2PNetwork) sendMessage(peerID peer.ID, protocolID protocol.ID, msg []byte) error {
	stream, err := n.host.NewStream(n.ctx, peerID, protocolID)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}
	defer stream.Close()

	if _, err := stream.Write(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func (n *P2PNetwork) discoveryLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			peers, err := n.dht.FindPeers(n.ctx, "atlys-network")
			if err != nil {
				continue
			}

			for p := range peers {
				if len(n.host.Network().Peers()) >= n.config.MaxPeers {
					break
				}
				if _, err := n.host.Network().DialPeer(n.ctx, p.ID); err != nil {
					continue
				}
			}
		}
	}
}

func (n *P2PNetwork) maintenanceLoop() {
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.mu.Lock()
			for id, node := range n.validators {
				if time.Since(node.LastSeen) > time.Hour {
					node.Status = StatusDisconnected
					delete(n.validators, id)
				}
			}
			n.mu.Unlock()

			// Ensure minimum peer count
			if len(n.host.Network().Peers()) < n.config.MinPeers {
				n.findNewPeers()
			}
		}
	}
}

func (n *P2PNetwork) findNewPeers() {
	peers, err := n.dht.FindPeers(n.ctx, "atlys-network")
	if err != nil {
		return
	}

	for p := range peers {
		if len(n.host.Network().Peers()) >= n.config.MinPeers {
			break
		}
		if _, err := n.host.Network().DialPeer(n.ctx, p.ID); err != nil {
			continue
		}
	}
}

func (n *P2PNetwork) GetPeerCount() int {
	return len(n.host.Network().Peers())
}

func (n *P2PNetwork) GetValidatorCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.validators)
}

func (n *P2PNetwork) IsValidator(peerID peer.ID) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	_, exists := n.validators[peerID]
	return exists
}

func (n *P2PNetwork) UpdateValidatorStatus(peerID peer.ID, status NodeStatus) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if node, exists := n.validators[peerID]; exists {
		node.Status = status
		node.LastSeen = time.Now()
	}
}
