// Package network implements the RPC server for the ATLYS protocol
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/atlys/pkg/bridge"
	"github.com/atlys/pkg/core"
	"github.com/atlys/pkg/types"
	"github.com/gorilla/mux"
)

// RPCServer handles RPC requests for the ATLYS protocol
type RPCServer struct {
	router     *mux.Router
	bridge     *bridge.Bridge
	validator  *core.Validator
	httpServer *http.Server
	config     *RPCConfig
}

// RPCConfig contains configuration parameters for the RPC server
type RPCConfig struct {
	ListenAddr     string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxHeaderBytes int
	EnableTLS      bool
	CertFile       string
	KeyFile        string
}

// RPCResponse represents a standardized JSON-RPC response
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewRPCServer creates a new instance of the RPC server
func NewRPCServer(bridge *bridge.Bridge, validator *core.Validator, config *RPCConfig) *RPCServer {
	server := &RPCServer{
		router:    mux.NewRouter(),
		bridge:    bridge,
		validator: validator,
		config:    config,
	}

	server.setupRoutes()
	return server
}

// Start initializes and starts the RPC server
func (s *RPCServer) Start() error {
	s.httpServer = &http.Server{
		Handler:        s.router,
		Addr:           s.config.ListenAddr,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		MaxHeaderBytes: s.config.MaxHeaderBytes,
	}

	if s.config.EnableTLS {
		return s.httpServer.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}
	return s.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the RPC server
func (s *RPCServer) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// setupRoutes configures the RPC server routes
func (s *RPCServer) setupRoutes() {
	// Transaction routes
	s.router.HandleFunc("/tx/submit", s.handleSubmitTransaction).Methods("POST")
	s.router.HandleFunc("/tx/status/{hash}", s.handleTransactionStatus).Methods("GET")

	// Chain state routes
	s.router.HandleFunc("/chain/status", s.handleChainStatus).Methods("GET")
	s.router.HandleFunc("/chain/block/{height}", s.handleGetBlock).Methods("GET")

	// Validator routes
	s.router.HandleFunc("/validator/status", s.handleValidatorStatus).Methods("GET")
	s.router.HandleFunc("/validator/register", s.handleValidatorRegistration).Methods("POST")

	// Bridge routes
	s.router.HandleFunc("/bridge/assets", s.handleBridgeAssets).Methods("GET")
	s.router.HandleFunc("/bridge/transfer", s.handleBridgeTransfer).Methods("POST")
}

// Transaction handlers

func (s *RPCServer) handleSubmitTransaction(w http.ResponseWriter, r *http.Request) {
	var tx types.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid transaction format", err)
		return
	}

	if err := s.bridge.ProcessCrossChainTx(r.Context(), &tx); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to process transaction", err)
		return
	}

	s.writeSuccess(w, map[string]interface{}{
		"hash":   tx.Hash().String(),
		"status": "submitted",
	})
}

func (s *RPCServer) handleTransactionStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hashStr := vars["hash"]

	hash, err := types.HashFromString(hashStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid transaction hash", err)
		return
	}

	status, err := s.bridge.GetTransactionStatus(hash)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "transaction not found", err)
		return
	}

	s.writeSuccess(w, status)
}

// Chain state handlers

func (s *RPCServer) handleChainStatus(w http.ResponseWriter, r *http.Request) {
	status := s.validator.GetChainStatus()
	s.writeSuccess(w, status)
}

func (s *RPCServer) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	heightStr := vars["height"]

	height, err := parseUint64(heightStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid block height", err)
		return
	}

	block, err := s.validator.GetBlock(height)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "block not found", err)
		return
	}

	s.writeSuccess(w, block)
}

// Validator handlers

func (s *RPCServer) handleValidatorStatus(w http.ResponseWriter, r *http.Request) {
	status := s.validator.GetStatus()
	s.writeSuccess(w, status)
}

func (s *RPCServer) handleValidatorRegistration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address   string `json:"address"`
		PublicKey string `json:"publicKey"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request format", err)
		return
	}

	if err := s.validator.RegisterValidator(req.Address, req.PublicKey, req.Signature); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to register validator", err)
		return
	}

	s.writeSuccess(w, map[string]string{
		"status":  "registered",
		"address": req.Address,
	})
}

// Bridge handlers

func (s *RPCServer) handleBridgeAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.bridge.GetRegisteredAssets()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to get assets", err)
		return
	}

	s.writeSuccess(w, assets)
}

func (s *RPCServer) handleBridgeTransfer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceChain string `json:"sourceChain"`
		DestChain   string `json:"destChain"`
		Asset       string `json:"asset"`
		Amount      string `json:"amount"`
		Recipient   string `json:"recipient"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request format", err)
		return
	}

	transferReq, err := s.bridge.InitiateTransfer(r.Context(), req.SourceChain, req.DestChain, req.Asset, req.Amount, req.Recipient)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to initiate transfer", err)
		return
	}

	s.writeSuccess(w, transferReq)
}

// Helper methods

func (s *RPCServer) writeSuccess(w http.ResponseWriter, result interface{}) {
	response := RPCResponse{
		JSONRPC: "2.0",
		ID:      nil, // Set based on request ID in production
		Result:  result,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *RPCServer) writeError(w http.ResponseWriter, status int, message string, err error) {
	rpcError := &RPCError{
		Code:    status,
		Message: message,
	}

	if err != nil {
		rpcError.Data = err.Error()
	}

	response := RPCResponse{
		JSONRPC: "2.0",
		ID:      nil, // Set based on request ID in production
		Error:   rpcError,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func parseUint64(s string) (uint64, error) {
	var value uint64
	if _, err := fmt.Sscanf(s, "%d", &value); err != nil {
		return 0, fmt.Errorf("invalid uint64 value: %s", s)
	}
	return value, nil
}

// Middleware

func (s *RPCServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Implement authentication logic here
		next(w, r)
	}
}

func (s *RPCServer) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		fmt.Printf("Request: %s %s took %v\n", r.Method, r.URL.Path, time.Since(start))
	}
}
