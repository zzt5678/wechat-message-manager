# Contributing

Contributions are welcome when they preserve the read-only and privacy boundaries.

Before opening a pull request:

1. Do not use real keys, account identifiers, paths, databases, installers, or chat samples as fixtures.
2. Keep Windows default capture free of Hooking, injection, process writes, restarts, and UI automation.
3. Keep the disabled Windows legacy route disabled until the hardening gates in `docs/emergency-downgrade.md` are implemented, fault-injected, and independently reviewed.
4. Keep macOS Hooking isolated to the explicit signed-copy command and separate copy/sign plus spawn/attach approvals.
5. Make every capture/import/refresh/query consume the same persisted dynamic database manifest; never reintroduce fixed shard counts.
6. Fail closed on a running WeChat process, nonempty WAL/rollback journal, source mutation, protected-store mismatch, or query-time freshness change.
7. Treat message bodies/names/links as untrusted input. Preserve explicit content/model approval, accurate per-command bounds, opaque duplicate-session selection, and the ban on exposing internal usernames/wxids.
8. Run `python -m compileall -q .`, `python -m unittest discover -s tests -v`, and `python scripts/secret_scan.py`.
9. Document platform/version claims precisely; distinguish current exact-commit live verification from historical, static, mocked, or CI validation.

For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public report with sensitive details.
