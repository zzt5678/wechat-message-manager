from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any

from manager_config import CORE_DATABASES, DECRYPTED_DIR, STATE_FILE, load_config, load_json
from refresh_vault import fingerprint
from secret_store import load_secret_json


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def normalize_timestamp(value: int | float | None) -> int:
    result = int(value or 0)
    while result > 10_000_000_000:
        result //= 1000
    return result


def as_time(value: int | float | None) -> str:
    timestamp = normalize_timestamp(value)
    return datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec="seconds") if timestamp else ""


def freshness_gate() -> dict[str, Any]:
    config = load_config()
    state = load_json(STATE_FILE, {})
    keys = load_secret_json().get("keys", {})
    if not isinstance(state, dict) or not isinstance(keys, dict):
        raise RuntimeError("STALE_VAULT: state or key store is unavailable")
    db_base = Path(str(config["db_base_path"]))
    for rel in CORE_DATABASES:
        if rel not in keys or rel not in state or not (DECRYPTED_DIR / rel).is_file():
            raise RuntimeError("STALE_VAULT: a core database is missing")
        if fingerprint(db_base / rel, str(keys[rel])) != state[rel]:
            raise RuntimeError("STALE_VAULT: source fingerprint changed; refresh first")
    return config


def contact_names() -> dict[str, str]:
    result: dict[str, str] = {}
    with connect(DECRYPTED_DIR / "contact/contact.db") as db:
        for row in db.execute("SELECT username, remark, nick_name FROM contact"):
            username = str(row["username"] or "")
            if username:
                result[username] = str(row["remark"] or row["nick_name"] or username)
    return result


def sessions() -> list[dict[str, Any]]:
    names = contact_names()
    no_contact: dict[str, str] = {}
    with connect(DECRYPTED_DIR / "session/session.db") as db:
        for row in db.execute("SELECT username, session_title FROM SessionNoContactInfoTable"):
            no_contact[str(row["username"])] = str(row["session_title"] or "")
        rows = db.execute(
            "SELECT username, type, unread_count, summary, last_timestamp, is_hidden "
            "FROM SessionTable ORDER BY sort_timestamp DESC"
        ).fetchall()
    return [
        {
            "_username": str(row["username"]),
            "_last_timestamp": normalize_timestamp(row["last_timestamp"]),
            "name": names.get(str(row["username"])) or no_contact.get(str(row["username"])) or "[未命名会话]",
            "type": int(row["type"] or 0),
            "unread": int(row["unread_count"] or 0),
            "last_time": as_time(row["last_timestamp"]),
            "preview": str(row["summary"] or "")[:160],
            "hidden": bool(row["is_hidden"]),
        }
        for row in rows
    ]


def resolve_session(label: str) -> dict[str, Any]:
    matches = [row for row in sessions() if row["name"].casefold() == label.casefold()]
    if not matches:
        matches = [row for row in sessions() if label.casefold() in row["name"].casefold()]
    if not matches:
        raise RuntimeError("No matching chat name")
    if len(matches) != 1:
        raise RuntimeError(f"AMBIGUOUS_CHAT_NAME: {len(matches)} chats match; use a more specific display name")
    return matches[0]


def message_location(username: str) -> tuple[Path, str] | None:
    table = "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()
    for index in range(4):
        path = DECRYPTED_DIR / f"message/message_{index}.db"
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
    content = row["message_content"]
    if isinstance(content, str) and content.strip():
        return content.strip()
    return f"[非文本消息 type={int(row['local_type'] or 0)}]"


def history(username: str, start: int, end: int, limit: int) -> list[dict[str, Any]]:
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
    for row in reversed(rows):
        sender_id = int(row["real_sender_id"] or 0)
        sender_username = senders.get(sender_id, "")
        output.append({
            "time": as_time(row["create_time"]),
            "sender": names.get(sender_username, "我" if sender_id == 0 else "群成员"),
            "type": int(row["local_type"] or 0),
            "text": message_text(row),
        })
    return output


def parse_time(value: str | None, fallback: datetime) -> int:
    if not value:
        return int(fallback.timestamp())
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return int(parsed.timestamp())


def public_session(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if not key.startswith("_")}


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


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Read-only queries against the verified private vault")
    sub = parser.add_subparsers(dest="command", required=True)
    status_parser = sub.add_parser("status")
    sessions_parser = sub.add_parser("sessions")
    sessions_parser.add_argument("--limit", type=int, default=20)
    sessions_parser.add_argument("--unread-only", action="store_true")
    history_parser = sub.add_parser("history")
    history_parser.add_argument("chat")
    history_parser.add_argument("--limit", type=int, default=100)
    history_parser.add_argument("--since")
    history_parser.add_argument("--until")
    digest_parser = sub.add_parser("digest-source")
    digest_parser.add_argument("--date", required=True)
    digest_parser.add_argument("--max-messages", type=int, default=3000)
    for item in (status_parser, sessions_parser, history_parser, digest_parser):
        item.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args()
    try:
        freshness_gate()
        now = datetime.now().astimezone()
        if args.command == "status":
            checks = {}
            for rel in CORE_DATABASES:
                with connect(DECRYPTED_DIR / rel) as db:
                    checks[rel] = db.execute("PRAGMA quick_check").fetchone()[0]
            emit({"status": "VERIFIED_FRESH_VAULT", "core_databases": checks}, args.format)
        elif args.command == "sessions":
            rows = [public_session(row) for row in sessions() if not args.unread_only or row["unread"] > 0]
            emit(rows[:max(1, min(args.limit, 500))], args.format)
        elif args.command == "history":
            session = resolve_session(args.chat)
            start = parse_time(args.since, now - timedelta(days=30))
            end = parse_time(args.until, now)
            emit(history(session["_username"], start, end, max(1, min(args.limit, 2000))), args.format)
        else:
            day = datetime.fromisoformat(args.date).replace(tzinfo=now.tzinfo)
            start, end = int(day.timestamp()), int((day + timedelta(days=1)).timestamp()) - 1
            remaining = max(1, min(args.max_messages, 10_000))
            chats = []
            for session in sessions():
                if remaining <= 0:
                    break
                if session["_last_timestamp"] < start:
                    continue
                messages = history(session["_username"], start, end, remaining)
                if messages:
                    chats.append({"chat": session["name"], "messages": messages})
                    remaining -= len(messages)
            emit({"date": args.date, "message_count": sum(len(c["messages"]) for c in chats), "chats": chats}, args.format)
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)[:500]}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
