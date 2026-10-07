# Roadmap

PSIRTMap is being built around one product-security workflow:

```text
shipped product release -> component inventory -> vulnerability match -> human decision
```

This roadmap is directional, not a delivery promise. Work is intentionally
ordered so every release remains small, testable, and useful on its own.

## At a glance

| Stage | Outcome | Status |
|---|---|---|
| Package check | Query one package version through OSV | Shipped in `v0.0.1` |
| Product inventory | Store products, releases, and components locally | Shipped in `v0.0.2` |
| Terminal dashboard | Manage inventory and scan releases interactively | Shipped in `v0.0.3` |
| SBOM import | Build release inventory from CycloneDX JSON | Shipped in `v0.0.4` |
| Local vulnerability data | Sync OSV data and scan from a local snapshot | Shipped in `v0.0.5` |
| Finding lifecycle | Persist matches and track what changed | Shipped in `v0.0.6` |
| Human assessment | Record impact decisions and evidence | Shipped in `v0.0.7` |
| KEV enrichment | Prioritize known exploitation | Shipped in `v0.0.8` |
| Offline feeds | Scan from validated, transferable feed bundles | Shipped in `v0.0.9` |
| Guided local UX | Install, launch, onboard, and transfer feeds without memorizing commands | Shipped in `v0.0.9` |
| Foundation hardening | Backups, compatibility fixtures, output contracts, fuzz seeds, and dependency vulnerability checks | Shipped in `v0.0.10` |
| Finding intelligence | Normalize severity and expose fixed boundaries, references, detail, filters, and deterministic priority | Shipped in `v0.0.10` |
| VEX | Export human assessments in a machine-readable format | Later |

## Shipped: foundation hardening

`v0.0.10` added a dedicated safety layer for future data-model changes:

- Consistent, private backups before existing SQLite databases migrate.
- A fixed v0.0.9 database fixture that future binaries must still read.
- Contract tests for automation-facing JSON output.
- Seed-corpus fuzz tests for CycloneDX and offline feed parsers.
- Reachability-aware Go vulnerability analysis in CI.
- Maintained architecture and threat-model documents.

## Shipped: finding intelligence

`v0.0.10` turns a bare match into a useful triage record without
pretending to make the human impact decision:

- Parse supported OSV CVSS vectors and retain both normalized severity and the
  source vector; unparseable or missing data remains `unknown`.
- Persist disclosure timestamps, advisory references, and package-specific
  fixed-version boundaries with each durable finding.
- Prioritize known exploitation first, then severity, source recency, and a
  stable identity tie-breaker.
- Filter finding lists by severity or CISA KEV membership.
- Inspect one component-level finding in text or deterministic JSON.
- Expose the same triage context in the terminal dashboard and offline feed
  workflow.

CVSS, KEV, and fixed boundaries remain prioritization evidence. They do not
replace product-specific exploitability assessment.

## Shipped: CycloneDX import

`v0.0.4` replaced most manual component entry with a single, transactional
import:

```sh
psirtmap release import AG-200@2.2 ./firmware-2.2.cdx.json
```

The implementation:

- Supports CycloneDX JSON 1.2 through 1.7.
- Reads the complete document before changing the database.
- Walks nested components and normalizes package URLs into OSV identities.
- Creates a missing release and imports its components atomically.
- Deduplicates document entries and repeated imports deterministically.
- Records source metadata and the document SHA-256 for provenance.
- Reports imported, already-present, duplicated, and skipped records clearly.
- Keeps manual component entry for demos and corrections.

## Shipped: local vulnerability data and matcher

`v0.0.5` moved vulnerability intelligence behind a stable local data model
instead of treating live API responses as the product's long-term matching
architecture:

- `psirtmap sync` queries every distinct package version in the inventory.
- OSV advisories, aliases, severity, affected packages, and ranges are stored
  locally with source and synchronization time.
- The complete snapshot is committed atomically only after every query succeeds.
- Normal release scans use exact matches from the local snapshot without an
  internet request.
- `scan --live` remains available as an explicit diagnostic path.

This first local matcher persists the authoritative result of OSV's exact
package-version query. Independent local range evaluation over a complete OSV
database remains a later scalability milestone.

## Shipped: persistent finding lifecycle

`v0.0.6` turns complete local scan results into durable workflow records:

- Each local scan records its release, data source, snapshot time, and counts.
- Matches are unique per release, component version, and vulnerability.
- Repeated scans distinguish new, existing, reopened, and no-longer-matched
  findings.
- Findings that stop matching remain available as historical evidence.
- `psirtmap findings` and the dashboard expose the active finding inventory.
- Direct `scan --live` checks remain diagnostic and cannot alter history.

## Shipped: human assessment

`v0.0.7` closes the first complete finding-to-decision loop:

- `psirtmap assess` records `investigating`, `affected`, `not-affected`, and
  `fixed` states.
- Final impact decisions require a reason.
- Reviewer, timestamp, optional evidence, and component identity are stored.
- Every decision is appended to history instead of overwriting the
  previous assessment.
- Re-scanning updates match evidence without resetting the human decision.
- The CLI and terminal dashboard both expose the current state and history.

## Shipped: CISA KEV enrichment

`v0.0.8` adds a second, independent prioritization source:

- `psirtmap sync` downloads and validates the official CISA KEV catalog.
- The catalog is stored locally with its source, version, release time, and
  synchronization time.
- Findings match KEV entries through either their primary identifier or CVE
  aliases.
- The CLI and dashboard show known-exploitation status and feed freshness.
- KEV remains prioritization context, not proof that a product is affected.
- A failed or malformed update cannot replace the last known-good catalog.

## Shipped: transferable offline feeds

`v0.0.9` makes synchronized intelligence portable to a machine that never
connects to the internet:

- `psirtmap feed pull` on a connected machine.
- `psirtmap feed export` to create a versioned, checksummed bundle.
- `psirtmap feed import` after a controlled transfer into the isolated network.
- Complete validation before imported data becomes active.
- Persistent provenance, source freshness, and import timestamps.
- Atomic OSV and KEV activation so a failed import preserves both previous
  snapshots.

## Offline and air-gapped operation

PSIRTMap is local-first: after an internet-connected `sync`, normal scans run
from SQLite without network access. Feed bundles also move fresh data into a
machine that never connects to the internet.

The supported flow is:

```text
connected machine              isolated environment

feed pull -> feed export  ->  controlled transfer  ->  feed import -> scan
```

The first bundle format provides:

- Versioned bundles with manifests and checksums.
- Inventory-scoped OSV data and the complete CISA KEV catalog.
- Source, creation time, import time, and staleness information.
- Complete validation before an imported feed becomes active.
- Explicit checksum and size validation before activation.

SHA-256 checksums detect transfer corruption but are not an authenticity
mechanism. Bundle signing and a configurable trust policy remain later work.

## Shipped: guided installation and first run

`v0.0.9` also makes the complete workflow accessible without memorizing CLI
syntax:

- Checksum-verifying macOS/Linux and Windows installers.
- `psirtmap` as the only command required to open the dashboard.
- A guided first-release import that creates the product, release, and
  component inventory atomically.
- File browsing from SBOM and feed-import forms.
- Choice-based assessment status instead of free-text status entry.
- A dashboard Feeds section for online updates and offline import/export.
- `psirtmap doctor` for local database, feed, and scan-readiness diagnostics.

## Later

- Signed feed bundles and configurable trusted signing keys.
- Homebrew, WinGet, and other native package-manager distribution.
- Full-ecosystem OSV data with independent local range evaluation.
- CycloneDX VEX export from human assessments.
- SPDX SBOM import.
- Product support lifecycle and end-of-life metadata.
- Finding ownership, due dates, fix releases, and evidence attachments.
- Human-approved security advisory generation.
- Deployed-device and customer exposure inventory.
- Regulatory report preparation without automatic submission.

## Explicit non-goals for the early product

Keeping the boundary clear is part of the product strategy. Early PSIRTMap is
not intended to become:

- A web UI or hosted SaaS.
- An identity, team, authentication, or RBAC system.
- A network, container, or firmware reverse-engineering scanner.
- An automatic patching or regulatory-submission service.
- A Jira or Slack integration hub.
- An AI, ML, or autonomous-agent product.
- A microservice, Redis, or Kubernetes deployment.

The core model remains:

```text
PRODUCT -> RELEASE -> COMPONENT -> VULNERABILITY -> FINDING -> ASSESSMENT
```
