# macOS workflow

Use `scripts/run_manager.py` followed by the arguments below.

```text
preflight
refresh --mode incremental
query digest-source --date today --format json
```

If keys are absent, prefer verified manual import:

```text
import-keys --file <private-json> --delete-source
```

If the user has no keys, show `capture-macos-plan`. The Frida signed-copy route is not the default and requires explicit approval in the current conversation. Never prepare, sign, launch, or attach to an app without that approval. The repository's macOS capture path has static/mock validation but still needs real-Mac verification.
