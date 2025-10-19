# tailnet Project Instructions

This document contains project-specific instructions for working on the tailnet codebase.

## Project Overview

Tailnet is a Go-based proxy manager built on Tailscale's tsnet library. It allows multiple named services on a Tailnet to be configured via a single TOML file.

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

- Build binary: `go build -o tailnet ./cmd/tailnet`
- Build with version info: `go build -ldflags "-X main.version=$(git describe --tags --always)" -o tailnet ./cmd/tailnet`
- Cross-compile for Linux: `GOOS=linux GOARCH=amd64 go build -o tailnet-linux-amd64 ./cmd/tailnet`
- Use Makefile: `make build` (automatically includes git SHA as version)

## Development Workflow

1. Follow TDD approach strictly
2. Write failing tests first before implementation
3. Use conventional commit format for all commits (e.g., `feat:`, `fix:`, `docs:`, `chore:`)
4. Update CHANGELOG.md for notable changes before release
5. Run linter and tests before marking any task complete
6. Pre-commit hooks are configured to run go-mod-tidy, go-fmt, and golangci-lint
7. Additional linting via golangci-lint includes go-vet, go-critic, gocognit, gocyclo, and gosec

## Project Structure

```
tailnet/
├── cmd/tailnet/        # Main application entry point
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

## Commit Message Conventions

- Use conventional commit format for all commits
- Common prefixes:
  - `feat:` - New features
  - `fix:` - Bug fixes
  - `docs:` - Documentation changes
  - `chore:` - Maintenance tasks (dependencies, build, etc.)
  - `test:` - Test changes
  - `refactor:` - Code refactoring without behavior change
  - `style:` - Code formatting, missing semicolons, etc.
  - `perf:` - Performance improvements
  - `ci:` - CI/CD configuration changes
- Include issue/PR number in parentheses when applicable: `fix: correct validation logic (#42)`

## Versioning and Release Process

- Follow [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH)
- Maintain CHANGELOG.md using [Keep a Changelog](https://keepachangelog.com/) format
- Update CHANGELOG.md before creating a release with all notable changes
- Releases are automated via GitHub Actions using GoReleaser
- Tag releases with `vX.Y.Z` format (e.g., `v0.3.1`)
- Release artifacts include:
  - Binary builds for multiple platforms
  - Docker images
  - Checksums and signatures

## Package Documentation Conventions

- Every package must have a package comment
- Format: `// Package <name> <verb> <description>.`
- Common verbs: provides, handles, implements, manages, defines
- Place package comment immediately before `package` declaration
- For complex packages, use multi-line comments with additional context
- Examples:
  ```go
  // Package config handles configuration parsing and validation for tailnet.
  package config
  
  // Package errors provides standardized error types and handling for tailnet.
  // It implements error classification, wrapping, and utility functions for
  // consistent error handling across the codebase.
  package errors
  ```

## Test Naming and Organization

### Test File Structure
- Unit tests: Place next to code (`file.go` → `file_test.go`)
- Integration tests: Place in `test/integration/`
- Test helpers: Place in `test/integration/helpers/`

### Test Function Naming
- Use descriptive `TestXxx` names that explain what's being tested
- Examples: `TestLoad`, `TestHTTPProxy`, `TestServiceHealthChecks`

### Table-Driven Tests
- Preferred pattern for multiple test cases
- Structure:
  ```go
  tests := []struct {
      name     string
      input    string
      expected string
      wantErr  bool
  }{
      {name: "valid case", input: "foo", expected: "bar"},
      // more cases...
  }
  
  for _, tt := range tests {
      t.Run(tt.name, func(t *testing.T) {
          // test implementation
      })
  }
  ```

### Test Utilities
- Use Testify for test assertions (`github.com/stretchr/testify/assert` and `github.com/stretchr/testify/require`)
- Use `assert` for non-critical assertions that can continue the test
- Use `require` for critical assertions that should stop the test immediately
- Use `t.Helper()` in test helper functions
- Use `t.Cleanup()` for resource cleanup
- Use `t.TempDir()` for temporary directories

### Testify Usage Examples
```go
// Use assert for non-critical checks
assert.Equal(t, expected, actual)
assert.NoError(t, err)
assert.True(t, condition)
assert.Contains(t, haystack, needle)

// Use require for critical checks that should stop the test
require.NoError(t, err)
require.NotNil(t, object)
```

## CI/CD Pipeline

- GitHub Actions workflows:
  - `ci.yml` - Runs on all pushes and PRs (tests, linting, builds)
  - `lint.yml` - Dedicated linting workflow
  - `release.yml` - Automated releases on version tags
- All code must pass CI checks before merging
- Integration tests run with `integration` build tag
- Race detection enabled in CI

## Pre-commit Hooks

- Automatically run before each commit:
  - `go-mod-tidy` - Ensures go.mod and go.sum are clean
  - `go-fmt` - Formats Go code
  - `golangci-lint` - Comprehensive linting
- Install hooks: `pre-commit install`
- Skip hooks (emergency only): `git commit --no-verify`
