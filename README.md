# PSIRTMap

Open-source vulnerability impact tracking for shipped products.

PSIRTMap is not another vulnerability scanner. It maps newly disclosed
vulnerabilities to the versions of products you have actually shipped.

Built for device, firmware, and embedded-software manufacturers. Local-first,
CLI-first, offline-capable, and written in Go.

## Current milestone: v0.0.1

The first working slice asks OSV for known vulnerabilities affecting one
package version:

```console
$ psirtmap check jinja2 2.4.1 --ecosystem PyPI
Package: jinja2@2.4.1
Ecosystem: PyPI

Found N OSV vulnerability records.

PYSEC-...
  ...
```

OSV ecosystem names are case-sensitive. A package name alone is not enough to
identify the package safely, so `--ecosystem` is required.

Machine-readable output is available with `--json`:

```console
$ psirtmap check lodash 4.17.20 --ecosystem npm --json
```

## Build and test

PSIRTMap currently requires Go 1.27 or newer and has no third-party runtime
dependencies.

```sh
go test ./...
go build -o psirtmap .
./psirtmap check jinja2 2.4.1 --ecosystem PyPI
```

## Product direction

The initial product scope is deliberately narrow:

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

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
