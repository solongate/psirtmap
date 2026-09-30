# Changelog

All notable changes to PSIRTMap are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.0.5] - 2026-09-30

### Added

- `psirtmap sync` for updating an inventory-scoped OSV snapshot in SQLite.
- Local vulnerability tables for advisories, aliases, severity, affected
  packages and ranges, exact package-version matches, source, and freshness.
- Offline-by-default release scanning from the active local snapshot.
- `psirtmap scan --live` for an explicit direct OSV query without changing the
  saved snapshot.
- Dashboard OSV synchronization and local-scan workflow.

### Changed

- OSV synchronization commits atomically only after all inventory package
  queries succeed; a failed update preserves the previous snapshot.
- Database schema migrated to version 3 without changing existing inventory.
- Version advanced to `0.0.5`.

## [0.0.4] - 2026-09-30

### Added

- Transactional CycloneDX JSON 1.2–1.7 import through
  `psirtmap release import`.
- Package URL parsing and normalization into supported OSV ecosystems.
- Nested component traversal, deterministic deduplication, skip reporting,
  document hashing, and SBOM import provenance.
- Automatic release creation after successful import validation.
- CycloneDX import flow in the terminal dashboard.
- An example AG-200 CycloneDX SBOM.
- Structured GitHub issue forms for reproducible bug reports and product
  feedback.
- A repository-owned terminal dashboard preview and SolonGate PSIRTMap logo.

### Changed

- Reorganized the README around the shipped product workflow, current
  limitations, installation, and a 60-second quick start.
- Reworked the roadmap, contribution guide, security policy, and third-party
  notices for clarity and consistency with the current release.
- Database schema migrated to version 2 without changing existing inventory.
- Version advanced to `0.0.4`.

## [0.0.3] - 2026-09-29

### Added

- Full-screen, keyboard-driven terminal dashboard.
- Responsive wide and compact terminal layouts.
- Dashboard views for inventory overview, products, releases, components, and
  live release scanning.
- Guided dashboard forms for creating products, releases, and components.
- Interactive help, status feedback, loading indicators, and safe quit/cancel
  behavior.
- Inventory-wide component listing for local dashboard views.
- A prioritized product roadmap with explicit near-term scope and non-goals.

### Changed

- Running `psirtmap` without arguments in an interactive terminal now opens
  the dashboard; non-interactive use still prints normal command help.
- Version advanced to `0.0.3`.

## [0.0.2] - 2026-09-29

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

[Unreleased]: https://github.com/solongate/psirtmap/compare/v0.0.5...HEAD
[0.0.5]: https://github.com/solongate/psirtmap/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/solongate/psirtmap/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/solongate/psirtmap/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/solongate/psirtmap/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/solongate/psirtmap/releases/tag/v0.0.1
