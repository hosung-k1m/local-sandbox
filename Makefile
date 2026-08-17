GO := ./bin/go

.PHONY: build guest test vet all clean

all: build guest

build:
	$(GO) build -o dist/boxedai ./cmd/boxedai

# Guest supervisor is cross-compiled for the VM; both arches so amd64 hosts work too.
guest:
	GOOS=linux GOARCH=arm64 $(GO) build -o dist/guest/boxedai-guest-agent-linux-arm64 ./guest/agent
	GOOS=linux GOARCH=amd64 $(GO) build -o dist/guest/boxedai-guest-agent-linux-amd64 ./guest/agent

test:
	$(GO) test ./cmd/boxedai ./guest/... ./internal/...

vet:
	$(GO) vet ./cmd/boxedai ./guest/... ./internal/...

clean:
	rm -rf dist
