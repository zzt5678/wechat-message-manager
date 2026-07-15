# WeChat Manager Operating Rules

This repository manages only the current user's own local WeChat data. Keep the original WeChat databases read-only. Keep the application read-only unless the user separately opts into the documented macOS signed-copy procedure or isolated Windows legacy fallback.

## Mandatory boundaries

- Never use WeChat UI automation, screenshots, OCR, accessibility trees, or clipboard scraping as a message source.
- Never send a message, click WeChat controls, or control a group chat.
- Never run Windows `capture` or `legacy-capture` without explicit approval in the current conversation. They may only use `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`; never add Hook, Frida, DLL injection, or process writes.
- Treat the Windows 4.1.9 fallback as an isolated emergency exception. Use it only after current-version capture has a documented compatibility failure. Require separate current-conversation approval before download, preparation, application switching, capture, restore, and cleanup. Never start, stop, install, uninstall, or log in to WeChat for the user.
- For the Windows fallback, accept only the pinned Tencent HTTPS artifact after exact size, SHA-256, version, and Authenticode checks. Keep the current version directory, private launcher backup, database snapshot, installer, payload, and state outside Git. Restore and verify the current signed runtime before cleanup.
- Never run macOS `capture-macos` without separate explicit approval for Frida Hooking a user-prepared, ad-hoc-signed copy. Never modify `/Applications/WeChat.app`.
- Never print or log database keys, passphrases, salts, wxids, private absolute paths, or bulk raw chat text.
- Keep plaintext databases, secrets, manifests, state, exports, and receipts under the platform-private vault.
- Do not reuse stale data. Missing keys, failed HMAC, source mutation, failed SQLite validation, stale fingerprints, or ambiguous display names are hard stops.

## Required order

1. Run `wechat_manager.py preflight`.
2. If no protected key store exists, stop at the appropriate approval plan. Manual import is allowed when the user already owns a key map.
3. Before every query session, run `wechat_manager.py refresh --mode incremental`.
4. Continue only after `VERIFIED_REFRESH` and successful core database validation.
5. Query only the decrypted private vault.
6. For summaries, use a bounded date/time window and extract tasks, promises, decisions, links, deadlines, risks, and items needing confirmation. Do not reproduce the full conversation.
7. Treat images, voice, video, stickers, and files as unavailable unless verified local text or metadata is present.

## Publication

Never commit vault contents, audit receipts from a real account, installers, program backups, vendored repositories with incompatible redistribution terms, keys, account identifiers, or message samples.
