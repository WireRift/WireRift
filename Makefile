.PHONY: build test test-cover test-race bench clean lint fuzz docker release

BINARY_SERVER=wirerift-server
BINARY_CLIENT=wirerift
VERSION?=1.4.1
GO=go
GOFLAGS=-v
PACKAGES=$(shell go list ./... | grep -v /website/)

build: build-server build-client

build-server:
	$(GO) build $(GOFLAGS) -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY_SERVER) ./cmd/wirerift-server

build-client:
	$(GO) build $(GOFLAGS) -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY_CLIENT) ./cmd/wirerift

test:
	$(GO) test $(GOFLAGS) $(PACKAGES) -timeout 120s

test-cover:
	$(GO) test $(PACKAGES) -cover -timeout 120s

test-race:
	$(GO) test -race $(PACKAGES) -timeout 180s

bench:
	$(GO) test -bench=. -benchmem $(PACKAGES)

fuzz:
	$(GO) test -fuzz=FuzzReadFrame -fuzztime=30s ./internal/proto/
	$(GO) test -fuzz=FuzzDecodeJSONPayload -fuzztime=30s ./internal/proto/
	$(GO) test -fuzz=FuzzDeserializeResponse -fuzztime=30s ./internal/server/
	$(GO) test -fuzz=FuzzExtractSubdomain -fuzztime=15s ./internal/server/

clean:
	rm -rf bin/
	rm -rf dist/
	rm -f coverage.out

lint:
	$(GO) vet $(PACKAGES)
	@which staticcheck > /dev/null 2>&1 && staticcheck $(PACKAGES) || echo "staticcheck not installed"
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run $(PACKAGES) || echo "golangci-lint not installed"

docker:
	docker build -t wirerift-server:$(VERSION) -t wirerift-server:latest .

release:
	@mkdir -p dist
	@for pair in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64; do \
		GOOS=$${pair%/*} GOARCH=$${pair#*/}; \
		EXT=""; [ "$$GOOS" = "windows" ] && EXT=".exe"; \
		echo "Building $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build -ldflags="-s -w -X main.version=$(VERSION)" \
			-o dist/$(BINARY_SERVER)-$$GOOS-$$GOARCH$$EXT ./cmd/wirerift-server; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build -ldflags="-s -w -X main.version=$(VERSION)" \
			-o dist/$(BINARY_CLIENT)-$$GOOS-$$GOARCH$$EXT ./cmd/wirerift; \
	done
