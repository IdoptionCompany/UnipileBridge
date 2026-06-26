# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Download deps first so this layer is cached unless go.mod/go.sum change.
# go.sum* glob lets the build work before go.sum is committed.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /unipile-bridge .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /unipile-bridge /unipile-bridge

EXPOSE 3000

ENTRYPOINT ["/unipile-bridge"]
