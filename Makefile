# Get version from git
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build
build:
	go build $(LDFLAGS) -o tailnet ./cmd/tailnet

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -f tailnet

.PHONY: run
run: build
	./tailnet $(ARGS)

.PHONY: integration
integration:
	go test -tags=integration ./test/integration/...

.PHONY: release
release:
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then \
		echo "Error: No version tag found. Please tag your release first."; \
		echo "Example: git tag v0.1.0 && git push origin v0.1.0"; \
		exit 1; \
	fi
	@echo "Building release $(VERSION)..."
	goreleaser release --clean

.PHONY: release-snapshot
release-snapshot:
	goreleaser release --snapshot --clean

.PHONY: docker-push-sha
docker-push-sha:
	@echo "Building and pushing Docker images with SHA: sha-$(shell git rev-parse --short HEAD)"
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t ghcr.io/sudosu404/tailnet-cli:sha-$(shell git rev-parse --short HEAD) \
		--push .