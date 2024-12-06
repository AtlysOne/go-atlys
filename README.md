# go-atlys
Implementation of the ATLAS blockchain project in Go

[ATLYS Blockchain Protocol](https://github.com/dewitt4/atlys-blockchain-protocol)

## Documentation

[Click here for the go-atlys documentation](https://github.com/dewitt4/atlys-blockchain-protocol/docs/go-atlys-documentation.md)

```
atlys/
├── cmd/
│   └── atlysd/
│       └── main.go         # Main entry point
├── pkg/
│   ├── core/
│   │   ├── block.go
│   │   ├── chain.go
│   │   └── transaction.go
│   ├── bridge/
│   │   ├── bridge.go
│   │   ├── state.go
│   │   └── assets.go
│   ├── consensus/
│   │   ├── validator.go
│   │   ├── reputation.go
│   │   └── voting.go
│   ├── crypto/
│   │   ├── keys.go
│   │   └── signing.go
│   ├── network/
│   │   ├── p2p.go
│   │   └── rpc.go
│   └── types/
│       └── types.go
├── internal/
│   ├── config/
│   │   └── config.go
│   └── store/
│       └── store.go
├── api/
│   └── v1/
│       └── api.go
├── docs/
├── scripts/
└── test/
```
