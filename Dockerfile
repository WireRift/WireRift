# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /wirerift-server ./cmd/wirerift-server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /wirerift ./cmd/wirerift

# Runtime stage
FROM scratch

COPY --from=builder /wirerift-server /wirerift-server
COPY --from=builder /wirerift /wirerift

EXPOSE 80 443 4040 4443

ENTRYPOINT ["/wirerift-server"]
