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
