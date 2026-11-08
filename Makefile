.PHONY: build test test-cover test-race bench clean lint fuzz docker release

BINARY_SERVER=wirerift-server
BINARY_CLIENT=wirerift
VERSION?=1.24.0
COMMIT?=$(shell git rev-parse --short=8 HEAD 2>/dev/null || echo none)
BUILD_DATE?=$(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
GO=go
GOFLAGS=-v
LDFLAGS=-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)
# Same package set as CI (the standalone test/advanced, test/benchmark, test/soak,
# test/fault and test/capacity programs are not part of it).
PACKAGES=./cmd/... ./internal/...

build: build-server build-client build-backup

build-server:
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY_SERVER) ./cmd/wirerift-server

build-client:
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$(BINARY_CLIENT) ./cmd/wirerift

build-backup:
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/wirerift-backup ./cmd/wirerift-backup

test:
	$(GO) test $(GOFLAGS) $(PACKAGES) ./test/integration/ -timeout 120s

test-cover:
	$(GO) test $(PACKAGES) -cover -timeout 120s

test-race:
	$(GO) test -race $(PACKAGES) ./test/integration/ -timeout 180s

bench:
	$(GO) test -bench=. -benchmem $(PACKAGES)

fuzz:
	$(GO) test -fuzz=FuzzReadFrame -fuzztime=30s ./internal/proto/
	$(GO) test -fuzz=FuzzDecodeJSONPayload -fuzztime=30s ./internal/proto/
	$(GO) test -fuzz=FuzzReadMagic -fuzztime=30s ./internal/proto/
	$(GO) test -fuzz=FuzzDeserializeResponse -fuzztime=30s ./internal/server/
	$(GO) test -fuzz=FuzzExtractSubdomain -fuzztime=15s ./internal/server/
	$(GO) test -fuzz=FuzzIsIPAllowed -fuzztime=30s ./internal/server/

clean:
	rm -rf bin/
	rm -rf dist/
	rm -f coverage.out

lint:
	$(GO) vet $(PACKAGES)
	@which staticcheck > /dev/null 2>&1 && staticcheck $(PACKAGES) || echo "staticcheck not installed"
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run $(PACKAGES) || echo "golangci-lint not installed"

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) -t wirerift-server:$(VERSION) -t wirerift-server:latest .

release:
	@mkdir -p dist
	@set -eu; for pair in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64; do \
		GOOS=$${pair%/*} GOARCH=$${pair#*/}; \
		EXT=""; [ "$$GOOS" = "windows" ] && EXT=".exe"; \
		echo "Building $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build -ldflags="$(LDFLAGS)" \
			-o dist/$(BINARY_SERVER)-$$GOOS-$$GOARCH$$EXT ./cmd/wirerift-server; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build -ldflags="$(LDFLAGS)" \
			-o dist/$(BINARY_CLIENT)-$$GOOS-$$GOARCH$$EXT ./cmd/wirerift; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build -ldflags="$(LDFLAGS)" \
			-o dist/wirerift-backup-$$GOOS-$$GOARCH$$EXT ./cmd/wirerift-backup; \
	done
