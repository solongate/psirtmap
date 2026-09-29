# Changelog

All notable changes to PSIRTMap are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Local SQLite inventory with automatic schema initialization.
- Product creation and listing.
- Product release creation and listing.
- Release component creation and listing.
- Release-wide OSV scanning with deterministic text and JSON output.
- Configurable database paths through `--database` and `PSIRTMAP_DB`.
- Dependency update automation and a private security-reporting policy.

### Changed

- Version advanced to `0.0.2`.
- CLI help now documents the complete inventory workflow.
- Equivalent OSV records are collapsed by their shared CVE, GHSA, and
  ecosystem advisory identifiers.
- Inventory identifiers and terminal output are hardened against control
  character injection.

## [0.0.1] - 2026-09-29

### Added

- Initial `psirtmap check` command for querying a package version through OSV.
- Human-readable and JSON output.
- Automated tests, cross-platform release builds, and Apache-2.0 licensing.

[Unreleased]: https://github.com/solongate/psirtmap/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/solongate/psirtmap/releases/tag/v0.0.1
