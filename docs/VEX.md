# Vulnerability Exploitability eXchange (VEX)

This document tracks third-party vulnerabilities that `govulncheck` or the CI
dependency review flags against a component PSIRTMap depends on, where a
maintainer has determined the vulnerability does not affect PSIRTMap. It is
maintained alongside the
[dependency vulnerability remediation policy](../SECURITY.md#dependency-vulnerability-remediation).

No entries currently apply: every vulnerability flagged to date has been
remediated by upgrading the affected dependency rather than assessed as
non-exploitable.

## Entry format

Each entry records, at minimum:

| Field | Description |
|---|---|
| Vulnerability ID | CVE or GHSA identifier |
| Component | Affected module and version |
| Status | `not_affected`, `affected`, or `fixed` |
| Justification | Why the vulnerability does not affect PSIRTMap, e.g. the vulnerable code path is unreachable or the affected feature isn't built or used |
| Assessed by | Maintainer who made the determination |
| Date | Date of assessment |

A `not_affected` entry is also recorded as a suppression in
`.github/dependency-review-config.yml`, with the pull request that adds it
linked here for traceability.
