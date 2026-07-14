# Contributing

Contributions are welcome when they preserve the read-only and privacy boundaries.

Before opening a pull request:

1. Do not use real keys, account identifiers, paths, databases, installers, or chat samples as fixtures.
2. Keep Windows default capture free of Hooking, injection, process writes, restarts, and UI automation.
3. Keep macOS Hooking isolated to the explicit signed-copy command and approval gate.
4. Run `python -m unittest discover -s tests -v` and `python scripts/secret_scan.py`.
5. Document platform/version claims precisely; distinguish live verification from static or mocked validation.

For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public report with sensitive details.
