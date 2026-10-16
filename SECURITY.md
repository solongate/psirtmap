# Security policy

We appreciate responsible reports that help keep PSIRTMap and its users safe.

## Supported versions

PSIRTMap is pre-1.0 software. Security fixes are applied to the latest released
version only.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Earlier releases | No |
| Unreleased forks or modified builds | No |

Before reporting, confirm the behavior against the
[latest release](https://github.com/solongate/psirtmap/releases/latest) when it
is safe to do so.

## Report a vulnerability

**Do not open a public issue for a suspected security vulnerability.**

Use GitHub's private
[security advisory form](https://github.com/solongate/psirtmap/security/advisories/new).
Please include:

- The affected PSIRTMap version and installation method.
- Operating system and architecture.
- A clear description of the issue and potential impact.
- Minimal reproduction steps or a proof of concept.
- Any known mitigations or suggested remediation.

Remove customer information, credentials, proprietary SBOMs, and unrelated
secrets from the report. If sensitive test data is essential, explain that
before sharing it.

## What to expect

SolonGate will review usable reports, investigate confirmed issues, and
coordinate remediation and disclosure with the reporter. Please allow time for
analysis before publishing details that could put users at risk.

| Milestone | Target |
|---|---|
| Acknowledgment of a new report | 3 business days |
| Initial assessment (triage, severity, affected versions) | 10 business days |
| Fix or mitigation for confirmed issues | 90 days, or sooner for actively exploited issues |

These are targets, not guarantees; SolonGate will communicate delays and keep
the reporter updated on progress.

## Scope clarification

PSIRTMap matches component versions against third-party vulnerability data. A
match is reported as **potentially affected** and does not replace a product-
security engineer's exploitability assessment.

Reports about an upstream package or an OSV record, without a vulnerability in
PSIRTMap itself, should be sent to the relevant upstream project or data
provider.

## Secrets management

PSIRTMap's CI and release pipelines use no long-lived secrets. Authenticating
to GitHub (creating releases, attesting build provenance) relies entirely on
the ephemeral, auto-rotated `GITHUB_TOKEN` issued per workflow run, scoped by
the `permissions:` block in each workflow file in `.github/workflows/`.

If a future integration needs a long-lived credential, it will be stored as a
GitHub Actions encrypted secret, scoped to the minimum required workflow, and
accessible only to the maintainers listed in
[MAINTAINERS.md](docs/MAINTAINERS.md). A secret is rotated immediately if a
maintainer's access is revoked or compromise is suspected, and is never
committed to the repository or echoed in workflow logs.

## Dependency vulnerability remediation

`govulncheck` runs on every pull request and push to `main`, and the
"Dependency review" CI check blocks a pull request that introduces a
dependency with a known vulnerability or a package flagged as malicious in the
GitHub Advisory Database (see [CONTRIBUTING.md](CONTRIBUTING.md)).

Remediation targets, measured from the date a vulnerability is first reported
against a dependency PSIRTMap ships:

| Severity | Remediate within |
|---|---|
| Critical | 7 days |
| High | 14 days |
| Medium | 30 days |
| Low | 90 days |

A release is not tagged while an applicable, unresolved vulnerability is open
against a dependency shipped in that release.

An advisory is suppressed only when a maintainer determines it does not apply
to PSIRTMap — for example, the vulnerable code path is unreachable or the
affected feature isn't built or used. Suppressions are declared explicitly as
an allowed GHSA ID in `.github/dependency-review-config.yml`, with the
justification recorded in the pull request that adds the suppression and
mirrored in the [VEX document](docs/VEX.md). A suppressed advisory still
follows the remediation targets above if it's later found to apply.

## Static analysis remediation

CodeQL performs static application security testing on every pull request and
push to `main`, and weekly on a schedule to pick up newly published queries.
Alerts appear under the repository's Security tab.

Remediation targets, measured from the date CodeQL first flags an alert:

| Severity | Remediate within |
|---|---|
| Critical / high (error) | 14 days |
| Medium (warning) | 30 days |
| Low (note) | 90 days |

A release is not tagged while an unresolved critical- or high-severity CodeQL
alert is open against code shipped in that release.

## Offline feed trust

PSIRTMap feed bundles use strict structure validation and SHA-256 checksums to
detect truncation and accidental modification. These checksums are stored in
the bundle itself and therefore do not authenticate the bundle's creator.

For creator authentication, generate an Ed25519 key pair on a controlled
staging machine, keep the private key secret, and provision the public key to
isolated systems through an independently trusted process. Export with
`--signing-key` and import with `--trusted-key`; supplying a trusted key makes
a valid signature mandatory. Imports without a trusted key retain legacy
compatibility but provide integrity only.

Treat an unexpected checksum, signature, manifest, signer, or source-timestamp
failure as a reason to reject the bundle and investigate the signing or
transfer path. If a private key may be compromised, stop trusting its public
key and rotate the pair manually.

The maintained [threat model](docs/THREAT_MODEL.md) documents current trust
boundaries, implemented controls, operator responsibilities, and limitations.
