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

## Scope clarification

PSIRTMap matches component versions against third-party vulnerability data. A
match is reported as **potentially affected** and does not replace a product-
security engineer's exploitability assessment.

Reports about an upstream package or an OSV record, without a vulnerability in
PSIRTMap itself, should be sent to the relevant upstream project or data
provider.
