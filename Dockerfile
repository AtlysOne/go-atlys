# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o atlysd ./cmd/atlysd

# Final stage
FROM alpine:3.18

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' atlys
USER atlys

# Copy binary from builder
COPY --from=builder /app/atlysd .

# Copy config files if needed
COPY --from=builder /app/config ./config

# Expose ports
EXPOSE 8545 26656 26657

# Set entrypoint
ENTRYPOINT ["./atlysd"]