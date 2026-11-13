# Build stage
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

ENV LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}"

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="${LDFLAGS}" -o /wirerift-server ./cmd/wirerift-server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="${LDFLAGS}" -o /wirerift ./cmd/wirerift
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /wirerift-backup ./cmd/wirerift-backup

# Runtime stage — minimal image with CA certs for ACME/TLS
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# Install CA certificates (required for Let's Encrypt ACME)
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 wirerift

COPY --from=builder /wirerift-server /usr/local/bin/wirerift-server
COPY --from=builder /wirerift /usr/local/bin/wirerift
COPY --from=builder /wirerift-backup /usr/local/bin/wirerift-backup

# Create cert storage directory
RUN mkdir -p /data/certs && chown wirerift:wirerift /data/certs

USER wirerift

EXPOSE 80 443 4040 4443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:80/health/ready || exit 1

ENTRYPOINT ["wirerift-server", "-cert-dir", "/data/certs", "-dashboard-bind", "0.0.0.0"]
