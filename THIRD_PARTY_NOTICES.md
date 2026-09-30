# Third-party notices

PSIRTMap depends on open-source software, including:

- `modernc.org/sqlite`, a pure-Go SQLite driver;
- `github.com/package-url/packageurl-go`, the Go implementation of the
  Package URL specification;
- Bubble Tea, Bubbles, and Lip Gloss from Charm for the terminal interface;
- their transitive runtime dependencies.

These components use their own licenses, primarily BSD-3-Clause and MIT.
SQLite itself is dedicated to the public domain. Exact dependency versions are
recorded in [`go.mod`](go.mod) and [`go.sum`](go.sum).

Release archives include the Package URL library license, the SQLite driver's
license, SQLite's public-domain notice, and the driver's generated third-party
license inventory. The presence of a third-party component does not imply
endorsement of PSIRTMap by its authors.
