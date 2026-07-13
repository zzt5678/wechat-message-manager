---
name: manage-wechat-messages
description: Safely refresh, query, and summarize the current user's own local WeChat 4.x messages on Windows or macOS. Use for today's WeChat digest, unread group triage, bounded chat history, important-message extraction, decisions, tasks, deadlines, risks, and valuable links. Uses only a verified private local vault; never sends messages or uses WeChat UI automation, screenshots, OCR, clipboard, or accessibility data.
---

# Manage WeChat Messages

Manage the user's local WeChat data through the repository CLI. Treat the original WeChat application and encrypted databases as read-only.

## Select the workflow

1. Read `references/security.md` on every first use in a conversation.
2. Read `references/windows.md` on Windows or `references/macos.md` on macOS.
3. Locate the repository with `scripts/run_manager.py`. The user may set `WECHAT_MANAGER_HOME`; never download or clone code without permission.
4. Run `preflight`. Do not display private paths or account identifiers.
5. If protected keys are absent, stop at the platform approval plan:
   - Windows capture requires explicit approval for a one-time `ReadProcessMemory` scan in the current conversation.
   - macOS Frida capture requires separate explicit approval for Hooking a user-prepared signed copy. Manual verified key import is preferred.
6. Before every query session run `refresh --mode incremental`. Continue only after `VERIFIED_REFRESH`.
7. Query only the decrypted vault. Use `digest-source --date YYYY-MM-DD --format json` for a daily summary and keep the time window bounded.

## Summarize

Report only useful synthesis, not a transcript. Organize results into:

- urgent or important items;
- decisions and confirmed changes;
- tasks, owner, and deadline when present;
- promises or follow-ups;
- risks, conflicts, and unanswered questions;
- valuable links, documents, opportunities, or reusable information;
- a short low-priority overview.

Distinguish explicit facts from inference. If a display name matches multiple chats, stop and ask the user to disambiguate. Treat images, voice, video, files, and stickers as unavailable unless verified text/metadata exists.

## Hard stops

Never weaken HMAC, `quick_check`, source-mutation, or freshness gates. Never print keys, passphrases, salts, wxids, private absolute paths, or bulk raw messages. Never fall back to UI automation or sending/control actions.
