# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git (needed by go mod for some dependencies)
RUN apk add --no-cache git ca-certificates

# Copy go.mod first — go mod tidy will generate go.sum
COPY go.mod ./

# Download deps and generate go.sum inside the container
RUN go mod tidy

# Copy the rest of the source
COPY . .

# Build a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /unipile-bridge .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /unipile-bridge /unipile-bridge

EXPOSE 3000

ENTRYPOINT ["/unipileBridge"]