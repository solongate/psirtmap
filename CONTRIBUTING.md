# Contributing

PSIRTMap is a maintainer-led open-source project developed by SolonGate.

The source is public so people can inspect, use, and learn from the project.
External code contributions are not currently accepted. This keeps product
direction and security-sensitive changes within a small, accountable
maintainer group while the data model is still evolving.

## Bug reports and product feedback

Focused reports are welcome through
[GitHub Issues](https://github.com/solongate/psirtmap/issues).

Before opening an issue:

1. Check that you are using the [latest release](https://github.com/solongate/psirtmap/releases/latest).
2. Search existing issues for the same behavior.
3. Remove credentials, customer data, and proprietary SBOM content.

A useful bug report includes:

- PSIRTMap version and installation method.
- Operating system and architecture.
- The command or dashboard action that triggered the problem.
- Minimal reproduction steps.
- Expected and actual behavior.
- Sanitized output or logs, when relevant.

Product feedback is most helpful when it describes the PSIRT workflow or
decision that is difficult today, rather than only proposing an interface.

## Security reports

Do not report suspected vulnerabilities in a public issue. Follow the private
process in [SECURITY.md](SECURITY.md).

## Pull requests

Please do not open a pull request unless a SolonGate maintainer has explicitly
requested it. Unsolicited pull requests may be closed without review.

Maintainer-requested changes should be small, focused, tested, and accompanied
by documentation when they alter user-visible behavior.

## Maintainer development checks

```sh
gofmt -w .
go mod verify
go vet ./...
go test -race -count=1 ./...
go build -trimpath ./...
```

By participating in the repository, you agree to communicate respectfully and
to avoid posting sensitive product, customer, or vulnerability information in
public threads.
