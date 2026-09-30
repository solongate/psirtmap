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
| Human assessment | Record impact decisions and evidence | Planned |
| KEV enrichment | Prioritize known exploitation | Planned |
| Offline feeds | Scan from validated, transferable feed bundles | Planned |
| VEX | Export human assessments in a machine-readable format | Later |

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
package-version query. Transferable full-feed bundles and independent local
range evaluation remain part of the offline-feed milestone.

## Shipped: persistent finding lifecycle

`v0.0.6` turns complete local scan results into durable workflow records:

- Each local scan records its release, data source, snapshot time, and counts.
- Matches are unique per release, component version, and vulnerability.
- Repeated scans distinguish new, existing, reopened, and no-longer-matched
  findings.
- Findings that stop matching remain available as historical evidence.
- `psirtmap findings` and the dashboard expose the active finding inventory.
- Direct `scan --live` checks remain diagnostic and cannot alter history.

## Next complete PSIRT workflow

Development now proceeds in this order.

### 1. Human assessment

- Support `investigating`, `affected`, `not-affected`, and `fixed` states.
- Require a reason for final impact decisions.
- Record reviewer, timestamp, evidence, and change history.
- Preserve earlier decisions instead of overwriting them silently.

### 2. CISA KEV enrichment

- Download and normalize the official KEV catalog.
- Mark findings with known exploitation.
- Display source and feed freshness.
- Treat KEV as prioritization context—not proof that a product is affected.

### 3. Stable operator workflow

- Expose import, findings, assessments, and KEV consistently in the dashboard
  and scriptable CLI.
- Add safe database backup and migration guidance.
- Publish end-to-end demo data and operator documentation.

## Offline and air-gapped operation

PSIRTMap is local-first today: after an internet-connected `sync`, normal scans
run from SQLite without network access. Moving fresh data into a machine that
never connects to the internet is not shipped yet.

The planned flow is:

```text
connected machine              isolated environment

feed pull -> feed export  ->  controlled transfer  ->  feed import -> scan
```

The implementation must provide:

- Versioned bundles with manifests and checksums.
- OSV data and CISA KEV metadata in a local matching database.
- Source, creation time, import time, and staleness information.
- Complete validation before an imported feed becomes active.
- A documented signing and trust model before secure-transfer claims are made.

## Later

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
