# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY . .

# Resolve imports and write go.sum at build time (no committed go.sum yet).
# Once go.sum is committed, this can be reverted to a cached `go mod download`.
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /unipile-bridge .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /unipile-bridge /unipile-bridge

EXPOSE 3000

ENTRYPOINT ["/unipile-bridge"]
