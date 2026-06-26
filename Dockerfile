# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Disable checksum DB and allow go.sum to be updated at build time
ENV GONOSUMDB=*
ENV GOFLAGS=-mod=mod

COPY . .

RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /unipile-bridge .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /unipile-bridge /unipile-bridge

EXPOSE 3000

ENTRYPOINT ["/unipile-bridge"]