# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Cache deps first
COPY go.mod go.sum ./
RUN go mod download

# Build a static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /unipile-bridge ./main.go

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /unipile-bridge /unipile-bridge
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 3000

ENTRYPOINT ["/unipile-bridge"]
