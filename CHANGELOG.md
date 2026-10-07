# Changelog

All notable changes to PSIRTMap are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Normalized CVSS 2.0, 3.0, 3.1, and 4.0 severity for durable findings, with
  explicit `unknown` handling when OSV does not provide a usable vector.
- Fixed-version boundaries, disclosure timestamps, source references, and raw
  CVSS context in finding records and the terminal dashboard.
- `psirtmap findings --severity`, `psirtmap findings --kev`, and
  `psirtmap findings show` for focused triage and detailed inspection.
- Deterministic KEV-first, severity-second, recency-third finding ordering.
- Consistent, `0600` SQLite snapshots before existing databases are migrated.
- A fixed v0.0.9 database compatibility fixture and automation-facing JSON
  output contract tests.
- Seed-corpus fuzz tests for CycloneDX JSON and offline feed bundle parsers.
- Architecture and threat-model documentation for the current local-first
  system.

### Changed

- Database schema migrated to version 8 while preserving v0.0.9 inventory,
  local intelligence, findings, and assessment history through a private
  pre-migration backup.

### Security

- CI now runs the official Go vulnerability analyzer against reachable code
  paths.
- A backup failure now prevents schema migration from starting.

## [0.0.9] - 2026-10-01

### Added

- `psirtmap feed pull`, `feed export`, and `feed import` for controlled
  vulnerability-intelligence transfer into disconnected environments.
- Versioned ZIP bundles containing inventory-scoped OSV matches and the
  complete CISA KEV catalog.
- A strict manifest with per-file sizes and SHA-256 checksums, bounded archive
  extraction, exact file allowlisting, and source-data validation.
- Persistent bundle source, creation time, import time, source freshness, and
  manifest digest provenance.
- Unit, rollback, and end-to-end offline scanning coverage.
- Guided first-run import that creates a product, release, and component
  inventory atomically from one CycloneDX JSON file.
- A dashboard Feeds section with online update, trusted bundle import, and
  bundle export actions.
- Terminal file browsing for SBOM and feed bundle selection.
- Choice-based assessment status selection in the dashboard.
- `psirtmap doctor` for installation, inventory, feed, and scan-readiness
  diagnostics.
- Checksum-verifying macOS/Linux and Windows installation scripts.

### Changed

- Feed import replaces OSV and KEV snapshots in one SQLite transaction; any
  validation or database failure preserves both last-known-good snapshots.
- Database schema migrated to version 7 without changing inventory, findings,
  scan audits, or assessment history.
- Version advanced to `0.0.9`.
- The dashboard now presents a context-aware primary action and compact,
  screen-specific controls; keyboard shortcuts remain optional.

### Fixed

- Replaced the stale dashboard claim that offline feeds were planned with
  live feed capability and provenance status.

### Security

- Bundle documentation distinguishes corruption-detecting checksums from
  creator authentication and requires a trusted transfer path until signing is
  implemented.

## [0.0.8] - 2026-10-01

### Added

- CISA Known Exploited Vulnerabilities catalog synchronization from CISA's
  canonical feed with its official GitHub mirror as a fallback.
- Strict catalog validation, deterministic normalization, response-size
  limits, and last-known-good local snapshot preservation.
- Local KEV catalog metadata and entries in SQLite.
- Alias-aware KEV enrichment for scan results and durable findings.
- Known-exploitation counts, feed freshness, required actions, due dates, and
  ransomware-use signals in the CLI and terminal dashboard.
- Unit, database lifecycle, and CLI workflow coverage for KEV data.

### Changed

- `psirtmap sync` now updates both inventory-scoped OSV data and the complete
  CISA KEV catalog.
- Database schema migrated to version 6 without changing inventory, OSV data,
  findings, scan audits, or assessment history.
- Version advanced to `0.0.8`.

## [0.0.7] - 2026-10-01

### Added

- Append-only human assessment history for component-level release findings.
- `investigating`, `affected`, `not-affected`, and `fixed` review states.
- Required reasons for final impact decisions, plus reviewer, timestamp, and
  optional evidence metadata.
- `psirtmap assess` for recording decisions and `psirtmap assess history` for
  inspecting the complete audit trail in text or JSON.
- Assessment status filtering through `psirtmap findings --status`.
- Finding assessment forms and latest-decision context in the terminal
  dashboard.

### Changed

- Finding review state and match lifecycle are represented separately, so a
  no-longer-matched record does not erase its human decision.
- Database schema migrated to version 5 without changing inventory, local OSV
  snapshots, finding history, or scan audits.
- Version advanced to `0.0.7`.

## [0.0.6] - 2026-09-30

### Added

- Durable finding records created by trusted local-snapshot release scans.
- Finding lifecycle reconciliation for new, existing, reopened, and
  no-longer-matched records without deleting historical evidence.
- `psirtmap findings [product@release]` with text, JSON, active-only, and
  `--all` history views.
- A Findings section and persistent lifecycle counters in the terminal
  dashboard.
- Scan audit records with release, data source, snapshot time, and lifecycle
  counts.

### Changed

- Normal local scans now save findings atomically after every complete match.
- `scan --live` is explicitly diagnostic and never changes finding history.
- Database schema migrated to version 4 without changing existing inventory or
  local OSV snapshots.
- Version advanced to `0.0.6`.

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

[Unreleased]: https://github.com/solongate/psirtmap/compare/v0.0.9...HEAD
[0.0.9]: https://github.com/solongate/psirtmap/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/solongate/psirtmap/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/solongate/psirtmap/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/solongate/psirtmap/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/solongate/psirtmap/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/solongate/psirtmap/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/solongate/psirtmap/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/solongate/psirtmap/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/solongate/psirtmap/releases/tag/v0.0.1
