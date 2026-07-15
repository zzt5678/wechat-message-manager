from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import date, datetime, time as datetime_time, timedelta
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, Iterator

from manager_config import (
    DECRYPTED_DIR, MESSAGE_SHARD_PATTERN, STATE_FILE, TOOL_VERSION,
    configured_core_databases, load_config, load_json, redact_private_text,
    operation_lock, require_supported_platform, require_wechat_stopped,
)
from refresh_vault import fingerprint
from secret_store import load_secret_json


MAX_MESSAGE_CHARS = 4_000
MAX_HISTORY_MESSAGES = 200
MAX_DIGEST_MESSAGES = 1_000
DEFAULT_QUERY_CHARS = 30_000
MAX_DIGEST_CHARS = 120_000
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
INTERNAL_ID_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:wxid_[A-Za-z0-9_-]{3,}|gh_[A-Za-z0-9_-]{3,}|[A-Za-z0-9_-]{5,}@chatroom)(?![A-Za-z0-9_-])"
)
BIDI_CONTROLS = dict.fromkeys(map(ord, "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"), None)


def output_limits() -> dict[str, int]:
    """Return non-content limits that callers can disclose before approval."""
    return {
        "per_message_chars_max": MAX_MESSAGE_CHARS,
        "sessions_max": 200,
        "session_name_chars_max": 200,
        "session_preview_chars_max": 160,
        "history_messages_max": MAX_HISTORY_MESSAGES,
        "digest_messages_default": 500,
        "digest_messages_max": MAX_DIGEST_MESSAGES,
        "untrusted_text_chars_default": DEFAULT_QUERY_CHARS,
        "untrusted_text_chars_max": MAX_DIGEST_CHARS,
    }


def bounded_char_budget(value: int) -> int:
    return max(1, min(value, MAX_DIGEST_CHARS))


def safe_text(value: object, limit: int = MAX_MESSAGE_CHARS) -> str:
    text = CONTROL_PATTERN.sub("", str(value or "")).translate(BIDI_CONTROLS)
    text = INTERNAL_ID_PATTERN.sub("[internal-id]", text)
    text = text.replace("\r\n", " ↩ ").replace("\r", " ↩ ").replace("\n", " ↩ ")
    text = text.replace("\t", " ").replace("\u2028", " ↩ ").replace("\u2029", " ↩ ")
    if len(text) <= limit:
        return text
    if limit <= 12:
        return text[:max(0, limit)]
    return text[: max(0, limit - 12)] + "[truncated]"


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def normalize_timestamp(value: int | float | None) -> int:
    result = int(value or 0)
    while result > 10_000_000_000:
        result //= 1000
    return result


def as_time(value: int | float | None) -> str:
    timestamp = normalize_timestamp(value)
    return datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec="seconds") if timestamp else ""


def freshness_gate() -> tuple[dict[str, Any], tuple[str, ...]]:
    config = load_config()
    if not config.get("db_base_path"):
        raise RuntimeError("CONFIGURATION_REQUIRED: run preflight --configure first")
    require_wechat_stopped()
    core_databases = configured_core_databases(config, verify_source=True)
    state = load_json(STATE_FILE, {})
    keys = load_secret_json().get("keys", {})
    if not isinstance(state, dict) or not isinstance(keys, dict):
        raise RuntimeError("STALE_VAULT: state or key store is unavailable")
    db_base = Path(str(config["db_base_path"]))
    for rel in core_databases:
        if rel not in keys or rel not in state or not (DECRYPTED_DIR / rel).is_file():
            raise RuntimeError("STALE_VAULT: a core database is missing")
        current = fingerprint(db_base / rel, str(keys[rel]))
        if int(current.get("wal_bytes", 0)) > 0 or int(current.get("journal_bytes", 0)) > 0:
            raise RuntimeError("STALE_VAULT: a source transaction log contains unsupported current transactions")
        if current != state[rel]:
            raise RuntimeError("STALE_VAULT: source fingerprint changed; refresh first")
    return config, core_databases


def contact_names() -> dict[str, str]:
    result: dict[str, str] = {}
    with connect(DECRYPTED_DIR / "contact/contact.db") as db:
        for row in db.execute("SELECT username, remark, nick_name FROM contact"):
            username = str(row["username"] or "")
            display_name = row["remark"] or row["nick_name"]
            if username and display_name and str(display_name) != username:
                # Internal usernames/wxids are lookup keys only and must never
                # become a display-name fallback.
                result[username] = safe_text(display_name, 200)
    return result


def session_tag_key() -> bytes:
    keys = load_secret_json().get("keys", {})
    if not isinstance(keys, dict) or not keys:
        raise RuntimeError("STALE_VAULT: key store is unavailable")
    serialized = json.dumps(
        sorted((str(name), str(value)) for name, value in keys.items()),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"wechat-manager-session-tag-v1\0" + serialized).digest()


def opaque_session_tag(username: str, tag_key: bytes) -> str:
    return hmac.new(tag_key, username.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def sessions() -> list[dict[str, Any]]:
    names = contact_names()
    tag_key = session_tag_key()
    no_contact: dict[str, str] = {}
    with connect(DECRYPTED_DIR / "session/session.db") as db:
        for row in db.execute("SELECT username, session_title FROM SessionNoContactInfoTable"):
            username = str(row["username"] or "")
            title = row["session_title"]
            if username and title and str(title) != username:
                no_contact[username] = safe_text(title, 200)
        rows = db.execute(
            "SELECT username, type, unread_count, summary, last_timestamp, is_hidden "
            "FROM SessionTable ORDER BY sort_timestamp DESC"
        ).fetchall()
    return [
        {
            "_username": str(row["username"]),
            "_session_tag": opaque_session_tag(str(row["username"]), tag_key),
            "_last_timestamp": normalize_timestamp(row["last_timestamp"]),
            "name": names.get(str(row["username"])) or no_contact.get(str(row["username"])) or "[未命名会话]",
            "type": int(row["type"] or 0),
            "unread": int(row["unread_count"] or 0),
            "last_time": as_time(row["last_timestamp"]),
            "preview": safe_text(row["summary"], 160),
            "hidden": bool(row["is_hidden"]),
        }
        for row in rows
    ]


def resolve_session(label: str | None = None, session_tag: str | None = None) -> dict[str, Any]:
    rows = sessions()
    if session_tag:
        matches = [row for row in rows if hmac.compare_digest(row["_session_tag"], session_tag)]
        if len(matches) != 1:
            raise RuntimeError("UNKNOWN_SESSION_TAG: rerun the approved sessions query")
        return matches[0]
    if not label:
        raise RuntimeError("CHAT_OR_SESSION_TAG_REQUIRED")
    matches = [row for row in rows if row["name"].casefold() == label.casefold()]
    if not matches:
        matches = [row for row in rows if label.casefold() in row["name"].casefold()]
    if not matches:
        raise RuntimeError("No matching chat name")
    if len(matches) != 1:
        raise RuntimeError(
            f"AMBIGUOUS_CHAT_NAME: {len(matches)} chats match; rerun sessions and use --session-tag"
        )
    return matches[0]


def message_location(username: str) -> tuple[Path, str] | None:
    table = "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()
    core_databases = configured_core_databases(load_config())
    for rel in core_databases:
        if not MESSAGE_SHARD_PATTERN.fullmatch(rel):
            continue
        path = DECRYPTED_DIR / rel
        with connect(path) as db:
            found = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
        if found:
            return path, table
    return None


def sender_map(db: sqlite3.Connection) -> dict[int, str]:
    return {int(row["rowid"]): str(row["user_name"] or "") for row in db.execute("SELECT rowid, user_name FROM Name2Id")}


def message_text(row: sqlite3.Row) -> str:
    local_type = int(row["local_type"] or 0)
    if local_type != 1:
        return f"[非文本消息 type={local_type}]"
    content = row["message_content"]
    if isinstance(content, str) and content.strip():
        return safe_text(content.strip())
    return "[空文本消息]"


def history(
    username: str, start: int, end: int, limit: int,
    max_chars: int = MAX_DIGEST_CHARS,
) -> list[dict[str, Any]]:
    location = message_location(username)
    if location is None:
        return []
    path, table = location
    names = contact_names()
    with connect(path) as db:
        senders = sender_map(db)
        query = (
            f'SELECT local_id, local_type, real_sender_id, create_time, message_content '
            f'FROM "{table}" WHERE create_time BETWEEN ? AND ? ORDER BY create_time DESC LIMIT ?'
        )
        rows = db.execute(query, (start, end, limit)).fetchall()
    output = []
    remaining_chars = max_chars
    for row in reversed(rows):
        if remaining_chars <= 0:
            break
        sender_id = int(row["real_sender_id"] or 0)
        sender_username = senders.get(sender_id, "")
        sender_value = names.get(sender_username, "我" if sender_id == 0 else "群成员")
        sender_budget = min(200, max(0, remaining_chars - 1))
        if len(sender_value) > sender_budget:
            sender_value = safe_text(sender_value, sender_budget) if sender_budget else ""
        text_value = message_text(row)
        text_budget = remaining_chars - len(sender_value)
        if text_budget <= 0:
            break
        if len(text_value) > text_budget:
            text_value = safe_text(text_value, text_budget)
        output.append({
            "time": as_time(row["create_time"]),
            "sender": sender_value,
            "type": int(row["local_type"] or 0),
            "text": text_value,
            "untrusted_content": True,
        })
        remaining_chars -= len(sender_value) + len(text_value)
    return output


def parse_time(value: str | None, fallback: datetime) -> int:
    if not value:
        return int(fallback.timestamp())
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return int(parsed.timestamp())


def local_midnight(value: date) -> datetime:
    """Resolve each local date independently so DST transitions stay correct."""
    return datetime.combine(value, datetime_time.min).astimezone()


def public_session(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **{key: value for key, value in row.items() if not key.startswith("_")},
        "session_tag": row["_session_tag"],
        "untrusted_content": True,
    }


def bounded_session_output(
    rows: list[dict[str, Any]], limit: int, max_chars: int,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    remaining_chars = bounded_char_budget(max_chars)
    for row in rows:
        if len(output) >= max(1, min(limit, 200)) or remaining_chars <= 0:
            break
        item = public_session(row)
        name = safe_text(item["name"], min(200, remaining_chars))
        remaining_chars -= len(name)
        preview = safe_text(item["preview"], min(160, remaining_chars)) if remaining_chars else ""
        remaining_chars -= len(preview)
        item["name"] = name
        item["preview"] = preview
        output.append(item)
    return output


def emit(value: Any, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            print(f"{key}: {item}")
    else:
        for row in value:
            if "text" in row:
                print(f"{row['time']}  {row['sender']}: {row['text']}")
            else:
                print(f"{row['last_time']}  unread={row['unread']:>3}  {row['name']}  {row['preview']}")


def require_content_output_approval(command: str, approved: bool) -> None:
    if command != "status" and not approved:
        raise RuntimeError(
            "MESSAGE_CONTENT_OUTPUT_APPROVAL_REQUIRED: selected text may enter the caller or model context"
        )


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Read-only queries against the verified private vault")
    sub = parser.add_subparsers(dest="command", required=True)
    status_parser = sub.add_parser("status")
    sessions_parser = sub.add_parser("sessions")
    sessions_parser.add_argument("--limit", type=int, default=20)
    sessions_parser.add_argument("--unread-only", action="store_true")
    sessions_parser.add_argument("--max-chars", type=int, default=DEFAULT_QUERY_CHARS)
    history_parser = sub.add_parser("history")
    history_parser.add_argument("chat", nargs="?")
    history_parser.add_argument("--session-tag")
    history_parser.add_argument("--limit", type=int, default=100)
    history_parser.add_argument("--since")
    history_parser.add_argument("--until")
    history_parser.add_argument("--max-chars", type=int, default=DEFAULT_QUERY_CHARS)
    digest_parser = sub.add_parser("digest-source")
    digest_parser.add_argument("--date", required=True, help="YYYY-MM-DD or today")
    digest_parser.add_argument("--max-messages", type=int, default=500)
    digest_parser.add_argument("--max-chars", type=int, default=DEFAULT_QUERY_CHARS)
    for item in (sessions_parser, history_parser, digest_parser):
        item.add_argument(
            "--i-understand-message-content-output", action="store_true",
            help="acknowledge that selected local message text will be returned to the caller",
        )
    for item in (status_parser, sessions_parser, history_parser, digest_parser):
        item.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args()
    try:
        require_supported_platform()
    except RuntimeError as exc:
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "FAILED",
            "error": str(exc),
        }, ensure_ascii=False), file=sys.stderr)
        return 2
    lock_context = operation_lock(STATE_FILE.with_name("manager.lock"))
    locked = False
    try:
        lock_context.__enter__()
        locked = True
        require_content_output_approval(
            args.command,
            bool(getattr(args, "i_understand_message_content_output", False)),
        )
        _, core_databases = freshness_gate()
        now = datetime.now().astimezone()
        if args.command == "status":
            checks = {}
            for rel in core_databases:
                with connect(DECRYPTED_DIR / rel) as db:
                    row = db.execute("PRAGMA quick_check").fetchone()
                result = str(row[0]) if row else ""
                if result.casefold() != "ok":
                    raise RuntimeError("VAULT_INTEGRITY_CHECK_FAILED: SQLite quick_check did not return ok")
                checks[rel] = "ok"
            output: Any = {
                "tool_version": TOOL_VERSION,
                "status": "VERIFIED_FRESH_VAULT",
                "core_databases": checks,
                "output_limits": output_limits(),
            }
        elif args.command == "sessions":
            output = bounded_session_output(
                [row for row in sessions() if not args.unread_only or row["unread"] > 0],
                args.limit,
                args.max_chars,
            )
        elif args.command == "history":
            if bool(args.chat) == bool(args.session_tag):
                raise RuntimeError("EXACTLY_ONE_OF_CHAT_OR_SESSION_TAG_REQUIRED")
            session = resolve_session(args.chat, args.session_tag)
            start = parse_time(args.since, now - timedelta(days=30))
            end = parse_time(args.until, now)
            output = history(
                session["_username"], start, end,
                max(1, min(args.limit, MAX_HISTORY_MESSAGES)),
                bounded_char_budget(args.max_chars),
            )
        else:
            day = (
                local_midnight(now.date())
                if args.date.casefold() == "today"
                else local_midnight(date.fromisoformat(args.date))
            )
            next_day = local_midnight(day.date() + timedelta(days=1))
            start, end = int(day.timestamp()), int(next_day.timestamp()) - 1
            remaining = max(1, min(args.max_messages, MAX_DIGEST_MESSAGES))
            remaining_chars = bounded_char_budget(args.max_chars)
            truncated = False
            chats = []
            for session in sessions():
                if remaining <= 0 or remaining_chars <= 0:
                    truncated = True
                    break
                if session["_last_timestamp"] < start:
                    continue
                chat_chars = len(session["name"])
                if remaining_chars <= chat_chars:
                    truncated = True
                    break
                messages = history(
                    session["_username"], start, end, remaining,
                    remaining_chars - chat_chars,
                )
                if messages:
                    message_chars = sum(
                        len(str(message["sender"])) + len(str(message["text"]))
                        for message in messages
                    )
                    chats.append({"chat": session["name"], "messages": messages})
                    remaining_chars -= chat_chars + message_chars
                    remaining -= len(messages)
            output = {
                "date": day.date().isoformat(),
                "message_count": sum(len(c["messages"]) for c in chats),
                "truncated": truncated or remaining <= 0 or remaining_chars <= 0,
                "untrusted_content": True,
                "chats": chats,
            }
        # No content is emitted if the encrypted source changed while the query
        # was being assembled.
        freshness_gate()
        emit(output, args.format)
        return 0
    except Exception as exc:
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "FAILED",
            "error": redact_private_text(exc),
        }, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        if locked:
            lock_context.__exit__(None, None, None)


if __name__ == "__main__":
    raise SystemExit(main())
