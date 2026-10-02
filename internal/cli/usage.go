package cli

import (
	"fmt"
	"io"
)

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `PSIRTMap maps vulnerabilities to software you ship.

Usage:
  psirtmap [--database <path>] <command>

Interactive:
  dashboard   Open the full-screen local dashboard (alias: ui)

Inventory commands:
  init        Initialize the local database
  product     Add and list products
  release     Add, import, and list product releases
  component   Add and list release components
  sync        Update local OSV and CISA KEV vulnerability intelligence
  feed        Pull, export, and import transferable offline feed bundles
  scan        Match a release and prioritize findings with local KEV data
  findings    List durable potential-impact findings
  assess      Record and inspect human impact decisions
  doctor      Check local installation, inventory, and feed readiness

Other commands:
  check       Query OSV for one package version
  version     Print the PSIRTMap version
  help        Show this help

Global options:
  -d, --database <path>  SQLite database path (default: ~/.psirtmap/psirtmap.db)

Run "psirtmap <command> --help" for command details.`)
}

func printCheckUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Query OSV for known vulnerabilities affecting a package version.

Usage:
  psirtmap check <package> <version> --ecosystem <ecosystem> [--json]

Examples:
  psirtmap check jinja2 2.4.1 --ecosystem PyPI
  psirtmap check lodash 4.17.20 --ecosystem npm --json

OSV ecosystem names are case-sensitive.`)
}

func printInitUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Initialize PSIRTMap's local SQLite database.

Usage:
  psirtmap [--database <path>] init`)
}

func printProductUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Manage products.

Usage:
  psirtmap product add <name> [--description <text>] [--json]
  psirtmap product list [--json]

"create" is accepted as an alias for "add".`)
}

func printReleaseUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Manage product releases.

Usage:
  psirtmap release add <product> <version> [--json]
  psirtmap release import <product>@<release> <bom.cdx.json> [--json]
  psirtmap release list [product] [--json]

Import accepts CycloneDX JSON versions 1.2 through 1.7. A missing release is
created atomically after the document and importable package identities have
been validated.

"create" is accepted as an alias for "add".`)
}

func printComponentUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Manage the components in a product release.

Usage:
  psirtmap component add <product>@<release> <package>@<version> --ecosystem <ecosystem> [--json]
  psirtmap component list <product>@<release> [--json]

Examples:
  psirtmap component add AG-200@2.2 openssl@3.0.8 --ecosystem Alpine
  psirtmap component add web@1.0 @scope/pkg@2.1.0 --ecosystem npm`)
}

func printScanUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Match every component in a product release against OSV data.

Usage:

  psirtmap scan <product>@<release> [--live] [--json]

The default scan uses the local OSV and CISA KEV snapshots created by
"psirtmap sync" and does not require internet access. Use --live to query OSV
directly without changing the saved OSV snapshot; KEV enrichment remains local.

A match means potentially affected and requires human review. A KEV match is a
prioritization signal, not proof that the product is exploitable.`)
}

func printSyncUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Update local vulnerability intelligence.

Usage:
  psirtmap [--database <path>] sync [--json]

Sync queries OSV for every distinct package version and downloads the CISA
Known Exploited Vulnerabilities catalog. It requires internet access. Downloads
and validation complete before new source snapshots are committed; malformed or
failed updates leave the previous local data available.`)
}

func printFeedUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Transfer vulnerability intelligence into a disconnected environment.

Usage:
  psirtmap [--database <path>] feed pull [--json]
  psirtmap [--database <path>] feed export [output.bundle] [--json]
  psirtmap [--database <path>] feed import <input.bundle> [--json]

"feed pull" downloads inventory-scoped OSV matches and the complete CISA KEV
catalog on an internet-connected machine. "feed export" packages the active
snapshots into a versioned ZIP bundle with per-file SHA-256 checksums. After a
controlled transfer, "feed import" validates the complete bundle before
atomically replacing both snapshots in the isolated database.

Checksums detect accidental corruption; they do not authenticate who created a
bundle. Accept bundles only through your organization's trusted transfer path.`)
}

func printFindingsUsage(writer io.Writer) {
	fmt.Fprintln(writer, `List findings saved by local release scans.

Usage:
  psirtmap findings [product@release] [--status <status>] [--all] [--json]

By default only active matches are shown. Use --all to include findings that no
longer match the current local OSV snapshot. Live scans are diagnostic and are
never written to the finding history. The KEV column is prioritization context,
not proof that a shipped product is exploitable.`)
}

func printAssessUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Record and inspect human impact decisions for a finding.

Usage:
  psirtmap assess <product>@<release> <vulnerability-id> \
    --status <status> --reviewer <name> [--reason <text>] \
    [--evidence <reference>] [--component <ecosystem:package@version>] [--json]

  psirtmap assess history <product>@<release> <vulnerability-id> \
    [--component <ecosystem:package@version>] [--json]

Statuses:
  investigating  Review is still in progress; a reason is optional.
  affected       The shipped release is affected; a reason is required.
  not-affected   The match is not exploitable in this release; a reason is required.
  fixed          The impact is remediated; a reason is required.

If the vulnerability matches multiple components in the same release, use
--component to select the exact component-level finding. Every decision is
appended to local history; earlier assessments are never overwritten.`)
}

func printDashboardUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Open PSIRTMap's interactive terminal dashboard.

Usage:
  psirtmap [--database <path>] dashboard

The dashboard reads and updates the same local SQLite inventory as the regular
commands. On an interactive terminal, running "psirtmap" without a command
opens the dashboard automatically.`)
}

func printDoctorUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Check the local PSIRTMap installation and scan readiness.

Usage:
  psirtmap [--database <path>] doctor [--json]

Doctor reports the database path, inventory counts, vulnerability-data
freshness, latest offline-feed import, and the next action when scanning is not
ready.`)
}
