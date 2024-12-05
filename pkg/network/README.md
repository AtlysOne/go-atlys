# Network

## Server Structure:

HTTP/JSON-RPC server using Gorilla Mux
Configurable TLS support
Timeout and request size limits
Graceful shutdown support


## API Endpoints:

Transaction submission and status
Chain state queries
Validator registration and status
Bridge operations and asset management


## Request Handling:

Standardized JSON-RPC response format
Comprehensive error handling
Input validation
Response formatting


## Features:

Middleware support for authentication and logging
TLS configuration
Request rate limiting capability
Status code handling



## Key endpoints include:

### Transaction Management:

/tx/submit - Submit new transactions
/tx/status/{hash} - Check transaction status


### Chain State:

/chain/status - Get current chain status
/chain/block/{height} - Get block by height


### Validator Operations:

/validator/status - Get validator status
/validator/register - Register new validator


### Bridge Operations:

/bridge/assets - Query registered assets
/bridge/transfer - Initiate cross-chain transfer