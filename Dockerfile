# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY . .

# GONOSUMDB=* skips checksum DB (avoids network issues in Railway build env)
# -mod=mod allows go to write go.sum entries on the fly during build
RUN go env -w GONOSUMDB="*" GONOSUMCHECK="*" && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" -o /unipile-bridge .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /unipile-bridge /unipile-bridge

EXPOSE 3000

ENTRYPOINT ["/unipile-bridge"]