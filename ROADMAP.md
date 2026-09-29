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
| SBOM import | Build release inventory from CycloneDX JSON | Next |
| Finding lifecycle | Persist matches and track what changed | Planned |
| Human assessment | Record impact decisions and evidence | Planned |
| KEV enrichment | Prioritize known exploitation | Planned |
| Offline feeds | Scan from validated, transferable feed bundles | Planned |
| VEX | Export human assessments in a machine-readable format | Later |

## Next: CycloneDX import

The next release will replace most manual component entry with a single,
transactional import:

```sh
psirtmap release import AG-200@2.2 ./firmware-2.2.cdx.json
```

Planned acceptance criteria:

- Support CycloneDX JSON first.
- Validate the complete document before changing the database.
- Import package URL (purl), ecosystem, name, and version when available.
- Deduplicate components deterministically.
- Report imported, skipped, and invalid records clearly.
- Keep manual component entry for demos and corrections.

## First complete PSIRT workflow

After SBOM import, development proceeds in this order.

### 1. Persistent findings

- Normalize and store vulnerability records locally.
- Record scan runs against specific product releases.
- Distinguish new, unchanged, and no-longer-matched findings.
- Preserve source records and matching evidence for auditability.
- Add filtering and deterministic JSON export.

### 2. Human assessment

- Support `investigating`, `affected`, `not-affected`, and `fixed` states.
- Require a reason for final impact decisions.
- Record reviewer, timestamp, evidence, and change history.
- Preserve earlier decisions instead of overwriting them silently.

### 3. CISA KEV enrichment

- Download and normalize the official KEV catalog.
- Mark findings with known exploitation.
- Display source and feed freshness.
- Treat KEV as prioritization context—not proof that a product is affected.

### 4. Stable operator workflow

- Expose import, findings, assessments, and KEV consistently in the dashboard
  and scriptable CLI.
- Add safe database backup and migration guidance.
- Publish end-to-end demo data and operator documentation.

## Offline and air-gapped operation

PSIRTMap is local-first today; its OSV scans still require internet access.
Air-gapped operation will ship only after the online matching workflow is
correct and auditable.

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
