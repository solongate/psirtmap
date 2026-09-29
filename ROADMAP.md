# PSIRTMap roadmap

PSIRTMap maps newly disclosed vulnerabilities to product versions that have
actually shipped. This roadmap keeps that product-security goal narrow and
orders work by the value it unlocks.

## Shipped

### v0.0.1 — One-package OSV check

- Query one ecosystem, package, and version through OSV.
- Human-readable and JSON output.

### v0.0.2 — Local shipped-product inventory

- Store products, releases, and components in local SQLite.
- Scan every component in a selected release through OSV.
- Report matches as `needs-review`, never as automatic proof of exploitability.

### v0.0.3 — Interactive terminal dashboard

- Full-screen, keyboard-driven local dashboard.
- Browse the complete product inventory.
- Create products, releases, and components through guided forms.
- Select and scan shipped releases without memorizing commands.
- Preserve regular CLI commands for scripts and automation.

## Next: complete the first useful PSIRT workflow

These are ordered. Each item should remain independently testable and
releasable.

### 1. CycloneDX JSON import

- `psirtmap release import <product>@<release> <bom.cdx.json>`.
- Validate the document before changing the database.
- Import package URL (purl), ecosystem, name, and version where available.
- Deduplicate components and print an import summary.
- Keep manual component entry for demos and corrections.

### 2. Persistent vulnerability and finding history

- Store normalized vulnerability records locally.
- Store scan runs and product-release findings.
- Distinguish new, unchanged, and no-longer-matched findings.
- Add `findings` filters and deterministic JSON export.
- Preserve the source record and matching evidence for auditability.

### 3. Human impact assessment

- Assessment states: `investigating`, `affected`, `not-affected`, and `fixed`.
- Require a reason for final impact decisions.
- Record reviewer, timestamp, evidence, and change history.
- Never overwrite earlier decisions silently.

### 4. CISA KEV enrichment

- Download and normalize the official KEV catalog.
- Mark findings with known exploitation.
- Show source and feed freshness.
- Use KEV as prioritization context, not as proof that a product is affected.

### 5. First stable workflow release

- Integrate SBOM import, persistent findings, assessments, and KEV in both the
  dashboard and scriptable CLI.
- Add safe database backup and migration guidance.
- Publish end-to-end demo data and operator documentation.

## Offline and air-gapped operation

This comes after the online workflow is correct. Until these items ship,
PSIRTMap is local-first but its OSV scan requires internet access.

- `feed pull`: download OSV data and CISA KEV on a connected machine.
- `feed export`: create a versioned bundle with a manifest and checksums.
- `feed import`: validate and load that bundle in the isolated environment.
- Match components entirely against the imported local feed.
- Expose feed source, creation time, import time, and staleness.
- Design bundle signing and trust policy before promising a secure transfer
  workflow.

## After the first stable workflow

- CycloneDX VEX export from human assessments.
- SPDX SBOM import.
- Product support lifecycle and end-of-life metadata.
- Finding ownership, due dates, fix releases, and evidence attachments.
- Security advisory generation with explicit human approval.
- Deployed-device and customer exposure inventory.
- Regulatory reporting preparation, without automatic submission.

## Explicit non-goals for the early product

- Web UI or SaaS hosting.
- Accounts, teams, authentication, or RBAC.
- Network, container, or firmware reverse-engineering scanners.
- Automatic patching or automatic regulatory submission.
- Jira, Slack, or other workflow integrations.
- AI, ML, or autonomous agents.
- Microservices, Redis, or Kubernetes.

The core model remains:

```text
PRODUCT -> RELEASE -> COMPONENT -> VULNERABILITY -> FINDING -> ASSESSMENT
```
