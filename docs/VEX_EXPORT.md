# CycloneDX VEX export

PSIRTMap can turn the human decisions stored for one shipped product release
into a standalone CycloneDX 1.6 VEX JSON document.

```sh
psirtmap vex export AG-200@2.2 ./AG-200-2.2.vex.cdx.json
```

If the output path is omitted, the file is created in the current directory as
`<product>-<release>.vex.cdx.json`. Existing files are never overwritten.

In the terminal dashboard, open **Findings**, select any finding in the target
release, and press `v`. PSIRTMap fills the release and a safe default filename;
review the values and press Enter to export.

## What is exported

The document contains one vulnerability entry for each component-level
finding that has at least one saved human assessment. The latest assessment is
the current decision, while the complete history contributes its first-issued
and last-updated timestamps.

| PSIRTMap assessment | CycloneDX analysis state |
|---|---|
| `investigating` | `in_triage` |
| `affected` | `exploitable` |
| `not-affected` | `not_affected` |
| `fixed` | `resolved` |

PSIRTMap also retains the reviewer, optional evidence reference, original
assessment status, finding activity, source aliases, current CISA KEV signal,
CVSS context, and safe advisory URLs where those values exist.

Unreviewed findings are intentionally absent. A version match is not exported
as an impact decision until a person records one.

## Assessment reasons and justifications

The saved reason is copied to CycloneDX `analysis.detail`. PSIRTMap does not
guess a structured `justification` from prose. For example, a reason containing
"feature disabled" is not automatically labeled `requires_configuration`.
This preserves what the reviewer actually recorded and avoids introducing an
unsupported technical claim.

## Offline and file behavior

Export reads the local SQLite database and performs no network request. The
document is created with private file permissions on supported systems. It is
fully encoded before publication, and an existing destination causes the
command to fail instead of replacing the file.

The document itself is not encrypted or signed. It can contain product names,
component versions, reviewer identity, assessment reasons, and evidence
references, so treat it as product-security data and transfer it through an
appropriate controlled path.

## Automation

`--json` changes the command summary, not the exported VEX document:

```sh
psirtmap vex export AG-200@2.2 ./AG-200-2.2.vex.cdx.json --json
```

The summary reports the absolute output path, CycloneDX version, product and
release, component and vulnerability counts, exported current decisions, total
assessment-history entries, and generation time.
