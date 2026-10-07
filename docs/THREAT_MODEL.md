# Threat model

This threat model covers the current local PSIRTMap CLI, SQLite database,
CycloneDX import, internet synchronization, and transferable feed bundles. It
is deliberately scoped to behavior the project ships today.

## Assets to protect

- Product names, shipped releases, and component inventory.
- Finding history, reviewer decisions, reasons, and evidence references.
- The integrity and freshness of OSV and CISA KEV data.
- The integrity of database migrations and offline feed imports.
- The availability of the last known-good local database.

## Trust boundaries

| Boundary | Treated as |
|---|---|
| User-selected CycloneDX document | Untrusted structured input |
| OSV and CISA HTTP responses | Untrusted until parsed and validated |
| Imported feed bundle | Untrusted until fully validated |
| Local SQLite file and transfer path | Controlled by the operator |
| Terminal and command arguments | Controlled by the local user |
| The installed PSIRTMap binary | Trusted by the operator |

## In-scope threats and controls

### Malformed or hostile SBOM data

- Input size and component nesting are bounded.
- JSON must contain one supported CycloneDX document.
- Package URLs are parsed and mapped through an allowlisted ecosystem model.
- Control characters and conflicting identities are rejected or reported as
  skipped.
- Persistent changes begin only after parsing and validation complete.
- Seed-corpus fuzz tests exercise the parser on every normal test run.

### Malformed or hostile feed bundles

- The archive has a total size limit and must contain exactly the expected
  regular files.
- Entry names, compressed contents, uncompressed sizes, JSON fields, counts,
  timestamps, and source records are validated.
- SHA-256 checksums cover every payload file.
- OSV and KEV activation occurs in one transaction after complete validation.
- Seed-corpus fuzz tests exercise bundle reading on every normal test run.

### Partial writes and destructive migrations

- SQLite transactions protect multi-table operations.
- A consistent, standalone SQLite backup is flushed to disk before an
  existing database is migrated.
- A backup failure stops the migration.
- The application refuses databases created by a newer schema version.
- A fixed v0.0.9 database fixture and migration tests protect compatibility.

### Vulnerable Go dependencies or standard library paths

- CI verifies the module download and checksum database state.
- `govulncheck` analyzes reachable Go vulnerability paths on every pull
  request and push to `main`.
- Race-enabled tests, `go vet`, and cross-platform builds run in CI.

### Accidental disclosure through synchronization

- OSV queries contain package ecosystem, name, and version only.
- CISA KEV is a one-way public catalog download.
- Full SBOM documents, product metadata, findings, assessments, and customer
  data remain local.

## Known limitations

- Feed checksums detect corruption but do not authenticate the creator.
  Signed bundles and configurable trusted keys are not yet implemented.
- The SQLite database is permission-restricted but not encrypted by PSIRTMap.
  Use operating-system disk encryption where confidentiality at rest matters.
- A user or process that can modify the database or replace the trusted binary
  is outside this model.
- Endpoint compromise, malicious operating-system components, terminal
  emulators, and physical attacks are outside this model.
- Upstream OSV or CISA data can be incomplete or incorrect. Human assessment
  remains required.
- Inventory-scoped OSV snapshots cover only package versions synchronized by
  the connected staging inventory.
- Evidence is currently stored as text or a reference; PSIRTMap does not
  encrypt, upload, or validate an external evidence repository.

## Operator responsibilities

- Obtain releases and checksums from the official repository.
- Protect the local account, database directory, and host storage.
- Review SBOM provenance before import.
- Use an approved, controlled path for offline bundle transfer.
- Investigate validation failures rather than bypassing them.
- Keep vulnerability intelligence fresh and have a person disposition each
  potentially affected finding.

Security issues in PSIRTMap should be reported privately using the process in
the [security policy](../SECURITY.md).
