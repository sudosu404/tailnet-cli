# tsbridge Project Instructions

This document contains project-specific instructions for working on the tsbridge codebase.

## Project Overview

tsbridge is a Go-based proxy manager built on Tailscale's tsnet library. It allows multiple named services on a Tailnet to be configured via a single TOML file.

## Testing Commands

- Run tests: `go test ./...`
- Run tests with coverage: `go test -cover ./...`
- Run tests with race detection: `go test -race ./...`
- Run specific test: `go test -run TestName ./path/to/package`

## Linting and Quality Checks

- Run linter: `golangci-lint run`
- Run go vet: `go vet ./...`
- Format code: `go fmt ./...`
- Check for formatting issues: `gofmt -l .`
- Run staticcheck: `staticcheck ./...`

## Build Commands

- Build binary: `go build -o tsbridge ./cmd/tsbridge`
- Build with version info: `go build -ldflags "-X main.version=$(git describe --tags --always)" -o tsbridge ./cmd/tsbridge`
- Cross-compile for Linux: `GOOS=linux GOARCH=amd64 go build -o tsbridge-linux-amd64 ./cmd/tsbridge`
- Use Makefile: `make build` (automatically includes git SHA as version)

## Development Workflow

1. Follow TDD approach strictly
2. Write failing tests first before implementation
3. Keep commits focused and use clear commit messages (no conventional commit prefixes)
4. Run linter and tests before marking any task complete
5. Pre-commit hooks are configured to run go-mod-tidy and go-fmt
6. Additional linting via golangci-lint includes go-vet, go-critic, gocognit, gocyclo, and gosec

## Project Structure

```
tsbridge/
├── cmd/tsbridge/        # Main application entry point
├── internal/            # Internal packages
│   ├── app/            # Application lifecycle management
│   ├── config/         # Configuration parsing and validation
│   ├── constants/      # Shared constants
│   ├── dialer/         # Network dialer implementations
│   ├── errors/         # Custom error types
│   ├── metrics/        # Prometheus metrics
│   ├── middleware/     # HTTP middleware (access logs, request ID, whois)
│   ├── proxy/          # Reverse proxy implementation
│   ├── service/        # Service registry and management
│   ├── tailscale/      # Tailscale integration utilities
│   ├── testutil/       # Test utilities
│   └── tsnet/          # Tailscale tsnet integration
├── test/               # Integration and e2e tests
│   └── integration/    # Integration test suite
│       └── helpers/    # Test helper utilities
├── example/            # Example backend server
└── docs/               # Documentation
```

## Key Dependencies

- Go 1.24+ required
- `tailscale.com` (v1.84.2) - Core Tailscale networking
- `github.com/prometheus/client_golang` - Metrics
- `github.com/knadh/koanf` - Configuration management

## Testing Guidelines

1. Unit tests go next to the code they test (e.g., `config.go` → `config_test.go`)
2. Integration tests go in `test/integration/`
3. Use table-driven tests for multiple scenarios
4. Mock external dependencies (tsnet, filesystem) for unit tests
5. Use real implementations for integration tests

## Error Handling

- Always return errors up the stack with context using `fmt.Errorf("context: %w", err)`
- Log errors at the point where they're handled, not where they're created
- Use structured logging fields for better observability
- Exit with non-zero status on startup failures

## Configuration

- Config loading order: CLI flags → TOML file → Environment variables
- Validate all config at startup, fail fast with clear messages
- Support both inline values and file/env references for secrets
- Global defaults can be overridden per-service

## Logging Standards

- Use structured logging with consistent field names
- Log levels: Debug (with -verbose flag), Info (default), Warn, Error
- Include service name in all service-specific logs
- Avoid logging sensitive data (OAuth tokens, etc.)
- Access logging is enabled by default, configurable via `access_log` in global or per-service config
- Access logs include: method, path, status, size, duration_ms, request_id, user_agent, remote_addr

## Metrics Conventions

- Prefix all metrics with `tsbridge_`
- Include `service` label for per-service metrics
- Follow Prometheus naming conventions
- Track: request counts, durations, error rates

## Security Considerations

- Never log OAuth credentials or secrets
- Use file-based or env-based secret injection
- Validate all backend addresses before dialing
- Set reasonable timeouts on all network operations

## Common Gotchas

1. tsnet requires OAuth client credentials - always validate these exist at startup
2. Unix socket paths must be absolute and start with `unix://`
3. Service names must be unique across the config
4. Graceful shutdown must wait for in-flight requests
5. Whois lookups can timeout - always enforce whois_timeout

## Useful Make Targets

The project includes a Makefile with these targets:

- `make build` - Build the binary with git SHA version
- `make test` - Run all tests
- `make lint` - Run all linters
- `make fmt` - Format all Go code
- `make vet` - Run go vet
- `make tidy` - Run go mod tidy
- `make clean` - Remove built binaries
- `make run ARGS="-config example.toml"` - Build and run with arguments
- `make integration` - Run integration tests with the integration build tag
- `make release` - Build release binaries using goreleaser
- `make release-snapshot` - Build release snapshot without tagging
