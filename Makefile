GO ?= go
export CGO_ENABLED ?= 0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test test-race lint fmt vet cover check run image clean

all: lint test

build:
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gateway ./cmd/gateway

# The race detector needs cgo, which this host's macOS SDK cannot link, so the
# default target runs without it. CI runs test-race on Linux.
test:
	$(GO) test -count=1 ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

cover:
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

lint: fmt vet

fmt:
	@unformatted=$$(gofmt -l . | grep -v '^$$' || true); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	$(GO) vet ./...

## check: validate the environment and policy without listening
check: build
	./bin/gateway -check

run:
	$(GO) run ./cmd/gateway

image:
	docker build --build-arg VERSION=$(VERSION) -t zero-trust-gateway:$(VERSION) .

clean:
	rm -rf bin coverage.out
