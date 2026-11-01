# Third-party notices

PSIRTMap depends on open-source software, including:

- `modernc.org/sqlite`, a pure-Go SQLite driver;
- `github.com/package-url/packageurl-go`, the Go implementation of the
  Package URL specification;
- `github.com/secengcommons/cvss`, an Apache-2.0-licensed CVSS 2.0, 3.0, 3.1,
  and 4.0 parser and score calculator;
- `github.com/CycloneDX/cyclonedx-go`, the Apache-2.0-licensed official Go
  model and encoder used to create CycloneDX VEX documents;
- `github.com/google/uuid`, the BSD-3-Clause-licensed UUID implementation used
  for document serial numbers and stable CycloneDX references;
- Bubble Tea, Bubbles, and Lip Gloss from Charm for the terminal interface;
- their transitive runtime dependencies.

These components use their own licenses, primarily Apache-2.0, BSD-3-Clause,
and MIT.
SQLite itself is dedicated to the public domain. Exact dependency versions are
recorded in [`go.mod`](go.mod) and [`go.sum`](go.sum).

Release archives include licenses and required notices for the Package URL,
CVSS, CycloneDX, UUID, and SQLite libraries; SQLite's public-domain notice; and
the SQLite driver's generated third-party license inventory. The presence of a
third-party component does not imply endorsement of PSIRTMap by its authors.
