# Architecture

PSIRTMap is a local-first Go CLI for mapping vulnerability intelligence to
shipped product releases. This document describes the architecture implemented
by the current pre-1.0 release, not a future service design.

## System boundary

```text
                               connected operation
                          +---------------------------+
                          | OSV API     CISA KEV feed |
                          +-----+-------------+-------+
                                |             |
                                v             v
CycloneDX JSON -> CLI/TUI -> validation -> SQLite database
                       |                       |
                       +---- local matcher <---+
                                  |
                                  v
                     finding -> human assessment

connected database -> checksummed feed bundle -> isolated database
```

The `psirtmap` process and one SQLite file are the complete runtime. There is
no PSIRTMap server, account, background daemon, browser UI, or database
service.

## Main components

| Component | Responsibility |
|---|---|
| CLI and terminal dashboard | Guide interactive work and expose scriptable commands |
| CycloneDX importer | Parse JSON, validate package URLs, normalize OSV identities, and record provenance |
| SQLite store | Persist inventory, intelligence, scans, findings, and append-only assessments |
| OSV client | Query exact ecosystem, package, and version combinations |
| CISA KEV client | Download and validate known-exploitation context |
| Finding intelligence | Normalize supported CVSS vectors and extract package-specific fixed boundaries and safe references |
| Local matcher | Read saved package-version matches without a network request |
| Feed bundle | Move OSV and KEV snapshots through a controlled offline transfer |

Package-specific parsing and network clients live outside the CLI layer. The
store owns transactions and persistence invariants; commands do not assemble
multi-table writes themselves.

## Core data flow

1. A CycloneDX JSON document creates or updates a `product -> release ->
   component` inventory.
2. `psirtmap sync` sends distinct component package identities and versions to
   OSV, and downloads the CISA KEV catalog.
3. Both validated snapshots are committed locally. A failed update preserves
   the previous usable data.
4. `psirtmap scan product@release` reads the local snapshot, derives
   deterministic triage context, reconciles durable findings, and never
   contacts a remote source.
5. A person records the product-impact decision and evidence as an append-only
   assessment.

The normal result is a **potential match**, not an automatic exploitability
decision.

Finding priority is deliberately explainable: CISA KEV membership, normalized
severity, OSV modification/publication time, then stable identity fields. No
opaque score or AI model is involved. CVSS parsing preserves the source vector;
missing or invalid vectors remain `unknown`. Fixed versions are range
boundaries reported by OSV, not product-specific remediation decisions.

## Network behavior

Only these explicit operations require network access:

- `psirtmap check`
- `psirtmap sync`
- `psirtmap feed pull`
- `psirtmap scan --live`

Normal scans, inventory management, finding review, assessments, feed export,
and feed import are local operations. OSV receives ecosystem, package name,
and version. Product names, release names, descriptions, findings,
assessments, and full SBOM documents are not sent to OSV or CISA.

## Persistence invariants

- SQLite foreign keys are enabled and multi-table changes use transactions.
- A failed sync, scan reconciliation, assessment write, or feed import cannot
  partially replace its last known-good state.
- Existing on-disk databases receive a consistent SQLite snapshot before a
  schema migration starts. Backups are stored beside the database as
  `*.pre-migration-vN-to-vM-*.backup` with `0600` permissions.
- New databases and already-current databases do not create redundant
  migration backups.
- Database schema compatibility is checked against a fixed v0.0.9 fixture.
- JSON output keys used by automation are protected by contract tests.

## Offline feed boundary

A feed bundle contains only vulnerability intelligence: inventory-scoped OSV
matches, the complete CISA KEV catalog, source timestamps, counts, and
provenance. It does not contain the product inventory or review history.

Bundle manifests, strict file allowlists, size limits, source validation, and
SHA-256 checksums detect corruption. They do not authenticate who created a
bundle. Until signed bundles ship, the transfer path is part of the trust
boundary.

## Compatibility policy before 1.0

Schema migrations are forward-only. PSIRTMap refuses to open a database whose
schema is newer than the binary supports. Before a release changes the schema,
it must preserve the previous release fixture, migration tests, CLI JSON
contracts, and transactional rollback behavior.

See the [threat model](THREAT_MODEL.md) for security assumptions and known
limitations.
