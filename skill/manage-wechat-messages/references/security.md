# Security rules

- Operate only on the current user's own local account data.
- Never use UI automation, OCR, screenshots, accessibility, or clipboard as a message source.
- Never send messages or control WeChat.
- Never expose keys, passphrases, salts, wxids, private paths, or bulk transcripts.
- Windows capture is allowed only after explicit approval for the current conversation and may use only query/read process rights.
- macOS Hook capture needs a separate explicit approval and may target only a user-prepared copy, never `/Applications/WeChat.app`.
- Require all core HMACs, per-page HMACs, stable source fingerprints, SQLite `quick_check`, and a fresh vault.
- If a gate fails, report the stage and stop. Do not substitute stale data.
