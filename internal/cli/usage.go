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
  sync        Update the local OSV snapshot for inventory packages
  scan        Match a release against the local OSV snapshot
  findings    List durable potential-impact findings
  assess      Record and inspect human impact decisions

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

The default scan uses the local snapshot created by "psirtmap sync" and does
not require internet access. Use --live to query OSV directly without changing
the saved snapshot.

A match means potentially affected and requires human review.`)
}

func printSyncUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Update the local OSV snapshot for every distinct package version in the inventory.

Usage:
  psirtmap [--database <path>] sync [--json]

Sync requires internet access. All OSV queries must succeed before the new
snapshot is committed, so a failed update leaves the previous snapshot intact.`)
}

func printFindingsUsage(writer io.Writer) {
	fmt.Fprintln(writer, `List findings saved by local release scans.

Usage:
  psirtmap findings [product@release] [--status <status>] [--all] [--json]

By default only active matches are shown. Use --all to include findings that no
longer match the current local OSV snapshot. Live scans are diagnostic and are
never written to the finding history.`)
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
