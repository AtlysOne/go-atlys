// pkg/network/p2p.go
package network

import (
    "context"
    "sync"
    
    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/protocol"
)

type P2PNetwork struct {
    host        host.Host
    validators  map[peer.ID]*ValidatorNode
    mu          sync.RWMutex
    protocols   map[protocol.ID]*Protocol
}

type Protocol struct {
    ID       protocol.ID
    Handler  ProtocolHandler
}

type ProtocolHandler interface {
    HandleMessage(ctx context.Context, msg []byte) error
}

func NewP2PNetwork(ctx context.Context, cfg *Config) (*P2PNetwork, error) {
    // Create libp2p host
    host, err := libp2p.New(
        libp2p.ListenAddrStrings(cfg.ListenAddresses...),
        libp2p.EnableRelay(),
    )
    if err != nil {
        return nil, err
    }

    return &P2PNetwork{
        host:       host,
        validators: make(map[peer.ID]*ValidatorNode),
        protocols:  make(map[protocol.ID]*Protocol),
    }, nil
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

// pkg/network/rpc.go
package network

import (
    "context"
    "encoding/json"
    "net/http"
    
    "github.com/gorilla/mux"
    "github.com/atlys/pkg/types"
)

type RPCServer struct {
    router  *mux.Router
    bridge  Bridge
}

type Bridge interface {
    ProcessCrossChainTx(ctx context.Context, tx *types.Transaction) error
}

func NewRPCServer(bridge Bridge) *RPCServer {
    r := mux.NewRouter()
    
    server := &RPCServer{
        router: r,
        bridge: bridge,
    }
    
    server.registerRoutes()
    return server
}

func (s *RPCServer) registerRoutes() {
    s.router.HandleFunc("/tx", s.handleTransaction).Methods("POST")
    s.router.HandleFunc("/status", s.handleStatus).Methods("GET")
}

func (s *RPCServer) handleTransaction(w http.ResponseWriter, r *http.Request) {
    var tx types.Transaction
    if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    if err := s.bridge.ProcessCrossChainTx(r.Context(), &tx); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    json.NewEncoder(w).Encode(map[string]string{
        "status": "success",
    })
}

// pkg/network/discovery.go
package network

import (
    "context"
    "time"
    
    "github.com/libp2p/go-libp2p/core/discovery"
    dht "github.com/libp2p/go-libp2p-kad-dht"
)

type Discovery struct {
    dht  *dht.IpfsDHT
    ctx  context.Context
}

func NewDiscovery(ctx context.Context, host host.Host) (*Discovery, error) {
    kdht, err := dht.New(ctx, host)
    if err != nil {
        return nil, err
    }
    
    return &Discovery{
        dht: kdht,
        ctx: ctx,
    }, nil
}

func (d *Discovery) Bootstrap() error {
    if err := d.dht.Bootstrap(d.ctx); err != nil {
        return err
    }
    
    // Start discovering peers
    go d.discoverPeers()
    
    return nil
}

func (d *Discovery) discoverPeers() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-d.ctx.Done():
            return
        case <-ticker.C:
            peers, err := d.dht.FindPeers(d.ctx, "atlys-network")
            if err != nil {
                continue
            }
            
            // Process discovered peers
            for p := range peers {
                // Handle new peer
                _ = p // Process peer
            }
        }
    }
}