# Build stage
FROM golang:1.23-alpine AS builder

# Label for safe cleanup
LABEL project=samnet-wg


# Install build dependencies with retry
RUN apk add --no-cache git build-base || (sleep 5 && apk add --no-cache git build-base) || (sleep 10 && apk add --no-cache git build-base)

WORKDIR /build

# Configure Go for reliable module downloads
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
ENV GOTOOLCHAIN=auto

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies with retry logic
RUN go mod download || \
    (echo "Retry 1..." && sleep 5 && go mod download) || \
    (echo "Retry 2..." && sleep 10 && go mod download) || \
    (echo "Retry 3..." && sleep 15 && go mod download)

# Copy source
COPY . .

# Ensure all transitive dependencies are properly recorded
RUN go mod tidy

# Build with optimizations and security hardening
RUN CGO_ENABLED=1 GOOS=linux go build -buildmode=pie -ldflags="-s -w" -o api main.go

# Runtime stage
FROM alpine:3.19

# Scoped project label for cleanup
LABEL project="samnet-wg"

# Install runtime dependencies
# Install runtime dependencies with aggressive retry
RUN apk update && apk add --no-cache wireguard-tools bash curl ca-certificates iptables \
    || (echo "Retry 1..." && sleep 15 && apk update && apk add --no-cache wireguard-tools bash curl ca-certificates iptables) \
    || (echo "Retry 2..." && sleep 30 && apk update && apk add --no-cache wireguard-tools bash curl ca-certificates iptables) \
    || (echo "Retry 3..." && sleep 60 && apk update && apk add --no-cache wireguard-tools bash curl ca-certificates iptables)

RUN addgroup -g 1000 samnet \
    && adduser -u 1000 -S samnet -G samnet

WORKDIR /home/samnet

# Copy binary from build stage
COPY --from=builder /build/api ./
COPY --from=builder /build/migrations ./migrations
COPY entrypoint.sh ./

# Set permissions
RUN chown -R samnet:samnet /home/samnet \
    && chmod 750 api entrypoint.sh

# Run as root to access /etc/wireguard and manage network interfaces
# USER samnet

EXPOSE 8766

# Use /health/ready for actual validation
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=30s \
    CMD wget -q --spider http://localhost:8766/health/ready || exit 1

CMD ["./entrypoint.sh"]
