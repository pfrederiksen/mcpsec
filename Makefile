.PHONY: build test lint clean install

BINARY := mcpsec
GO := go

build:
	$(GO) build -o bin/$(BINARY) ./cmd/mcpsec

test:
	$(GO) test ./... -race

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
	rm -f coverage.out

install:
	$(GO) install ./cmd/mcpsec
