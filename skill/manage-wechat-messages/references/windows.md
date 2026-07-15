# Windows workflow

Use `scripts/run_manager.py` followed by the arguments below.

```text
preflight
capture-plan
refresh --mode incremental
query digest-source --date today --format json
```

If preflight shows no protected keys, show the non-executing `capture-plan` and request explicit consent. Only after consent:

```text
capture --i-understand-read-process-memory
```

Expected success is `VERIFIED_CURRENT_VERSION_READ_ONLY_RECOVERY`. It directly supports the current installed version when its layout matches; do not ask the user to downgrade unless the current method is incompatible and the user separately requests the emergency route.

## Emergency 4.1.9 fallback

Use only after a documented current-capture compatibility failure. First show:

```text
legacy-plan
```

Read the repository `docs/emergency-downgrade.md` completely before acting. Require a fresh, separate approval before each mutating or sensitive command:

```text
legacy-download --i-understand-download-legacy-installer
legacy-prepare --i-understand-prepare-private-backup
legacy-switch --i-understand-temporary-version-switch
legacy-capture --i-understand-read-process-memory
legacy-restore --i-understand-restore-current-version
legacy-verify-restored
legacy-cleanup --i-understand-remove-installed-legacy-copy
```

The user must manually exit, start, and log in to WeChat at the documented boundaries. `legacy-switch`, `legacy-restore`, and `legacy-cleanup` require Administrator PowerShell. Never bypass the pinned Tencent URL, size, SHA-256, exact versions, Authenticode, state, snapshot, seven-database HMAC, restore, or full-refresh gates.
