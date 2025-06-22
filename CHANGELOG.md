# Changelog

All notable changes to tsbridge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-06-21

### Added

- TLS certificate priming on startup to avoid ~1 minute delay on first HTTPS request
  - Automatically primes certificates in the background after service starts
  - Only applies to services using TLS auto mode
  - Non-blocking operation that doesn't delay service startup

### Documentation

- Added HSTS header examples to documentation
- Updated README with OAuth credential provisioning instructions
- Moved AI agent rules to generic RULES.md file

## [0.1.0] - 2025-06-21

### Added

- Initial release of tsbridge - a lightweight proxy manager built on Tailscale's tsnet library

[0.2.0]: https://github.com/jtdowney/tsbridge/releases/tag/v0.2.0
[0.1.0]: https://github.com/jtdowney/tsbridge/releases/tag/v0.1.0
