GO := ./bin/go

.PHONY: build guest test vet mediated-workspace-e2e all clean

all: build guest

build:
	$(GO) build -o dist/boxedai ./cmd/boxedai
	$(GO) build -o dist/boxedai-ssh-proxy ./cmd/boxedai-ssh-proxy

# Guest supervisor is cross-compiled for the VM; both arches so amd64 hosts work too.
guest:
	GOOS=linux GOARCH=arm64 $(GO) build -o dist/guest/boxedai-guest-agent-linux-arm64 ./guest/agent
	GOOS=linux GOARCH=amd64 $(GO) build -o dist/guest/boxedai-guest-agent-linux-amd64 ./guest/agent

test:
	$(GO) test ./cmd/boxedai ./guest/... ./internal/...

vet:
	$(GO) vet ./cmd/boxedai ./guest/... ./internal/...

# Runs only against a disposable, already-started mediated session. It first
# refuses an image that cannot exercise the FUSE mediator, before it performs
# any workspace mutation. Example:
# make mediated-workspace-e2e LIMA_INSTANCE=bx-...
mediated-workspace-e2e:
	./scripts/mediated-workspace-e2e.sh "$(LIMA_INSTANCE)"

clean:
	rm -rf dist
