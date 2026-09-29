# PSIRTMap

Open-source vulnerability impact tracking for shipped products.

PSIRTMap is not another vulnerability scanner. It maps newly disclosed
vulnerabilities to the versions of products you have actually shipped.

Built for device, firmware, and embedded-software manufacturers. Local-first,
CLI-first, and written in Go. Offline feed support is planned.

## Current milestone: v0.0.3

PSIRTMap now includes a full-screen terminal dashboard for managing the local
inventory and scanning shipped releases without memorizing commands. The
scriptable commands remain available for automation.

## Interactive dashboard

Run PSIRTMap in an interactive terminal:

```console
$ psirtmap
```

You can also launch the dashboard explicitly, including with a separate test
database:

```console
$ psirtmap dashboard
$ psirtmap --database ./demo.db dashboard
```

The dashboard provides:

- A live overview of products, releases, and components in local SQLite.
- Browsable product, release, and component inventories.
- Guided forms for creating products, releases, and components.
- Release selection and live OSV scanning with review-safe wording.
- Responsive wide and compact terminal layouts.

Main keys:

```text
↑/↓ or j/k   move through sections or rows
←/→ or h/l   focus navigation or content
1–5            open a section directly
n              create an item in the current section
s or Enter     scan the selected release
r              refresh the local inventory
?              show keyboard help
q              quit
```

The dashboard and regular commands use the same database. Nothing is uploaded
to a PSIRTMap cloud service.

## Scriptable CLI quick start

Initialize the local SQLite database:

```console
$ psirtmap init
Initialized PSIRTMap database:
/Users/you/.psirtmap/psirtmap.db
```

Create a product and a shipped release:

```console
$ psirtmap product add AG-200 --description "Industrial gateway"
Created product:
AG-200

$ psirtmap release add AG-200 2.2
Created release:
AG-200@2.2
```

Record the components in that release. OSV ecosystem names are case-sensitive:

```console
$ psirtmap component add AG-200@2.2 openssl@3.0.8 --ecosystem Alpine
$ psirtmap component add AG-200@2.2 busybox@1.36.0 --ecosystem Alpine
```

Inspect and scan the release:

```console
$ psirtmap component list AG-200@2.2
ECOSYSTEM  COMPONENT  VERSION
Alpine     busybox    1.36.0
Alpine     openssl    3.0.8

$ psirtmap scan AG-200@2.2
PRODUCT RELEASE
AG-200 2.2

COMPONENTS
2

POTENTIAL FINDINGS
...
```

Every match is reported as `needs-review`: a package-version match is evidence
of potential impact, not proof that the shipped product is exploitable.

The original one-package OSV query remains available:

```console
$ psirtmap check jinja2 2.4.1 --ecosystem PyPI
Package: jinja2@2.4.1
Ecosystem: PyPI

Found N OSV vulnerability records.

PYSEC-...
  ...
```

A package name alone is not enough to identify a package safely, so
`--ecosystem` is required.

Inventory lists, create commands, `check`, and `scan` support machine-readable
output with `--json`:

```console
$ psirtmap product list --json
$ psirtmap scan AG-200@2.2 --json
```

Run `psirtmap help` or `psirtmap <command> --help` for the complete CLI usage.

## Local database

The default database is `~/.psirtmap/psirtmap.db`. PSIRTMap creates it with
permissions `0600` and automatically applies compatible schema migrations.
There is no database server, account, or cloud service.

Use another database for testing or separate inventories:

```sh
psirtmap --database ./demo.db product list
```

The `PSIRTMAP_DB` environment variable can also set the path. The explicit
`--database` option takes precedence.

## Install

Download the archive for your operating system from the
[latest release](https://github.com/solongate/psirtmap/releases/latest), then
verify it against `checksums.txt` before extracting it.

Go users can install the latest tagged version directly:

```sh
go install github.com/solongate/psirtmap@latest
```

## Build and test

PSIRTMap requires Go 1.27 or newer. SQLite is embedded in the resulting binary,
so users do not need to install SQLite or any other runtime service.

```sh
go test ./...
go test -race -count=1 ./...
go vet ./...
go build -o psirtmap .
./psirtmap --database ./demo.db init
```

CI runs formatting, vet, race-enabled tests, and a clean build for every pull
request.

## Product direction

The product scope remains deliberately narrow:

1. Create products and releases.
2. Import CycloneDX JSON SBOMs.
3. Keep component inventory locally.
4. Synchronize OSV vulnerability data and CISA KEV metadata.
5. Match components to vulnerabilities and shipped product releases.
6. Record human impact assessments.

The core model is:

```text
PRODUCT -> RELEASE -> COMPONENT -> VULNERABILITY -> FINDING -> ASSESSMENT
```

PSIRTMap reports a package-version match as **potentially affected**. A human
review determines whether the shipped product is actually affected.

Today, `scan` queries OSV live. Persisted vulnerability feeds, CISA KEV
enrichment, CycloneDX import, findings history, and human assessments are the
next milestones; the CLI does not pretend those features exist yet. See
[ROADMAP.md](ROADMAP.md) for the ordered delivery plan and explicit non-goals.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE),
[NOTICE](NOTICE), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
