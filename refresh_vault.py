from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile

from Crypto.Cipher import AES

from secret_store import load_secret_json
from manager_config import (
    AUDIT_DIR, CORE_DATABASES, DECRYPTED_DIR, MANIFEST_DIR, STATE_FILE,
    PRIVATE_ROOT, atomic_write_json, ensure_private_tree, load_config, load_json, public_path_label,
)


PAGE_SIZE = 4096
RESERVE_SIZE = 80
IV_SIZE = 16
HMAC_SIZE = 64
SQLITE_HEADER = b"SQLite format 3\x00"


def fingerprint(path: Path, key_hex: str) -> dict[str, object]:
    stat = path.stat()
    return {
        "source_bytes": stat.st_size,
        "source_mtime_ns": stat.st_mtime_ns,
        "key_sha256": hashlib.sha256(bytes.fromhex(key_hex)).hexdigest(),
    }


def hmac_key(key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(value ^ 0x3A for value in salt)
    return hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)


def verify_page(page: bytes, page_number: int, mac_key: bytes) -> None:
    start = 16 if page_number == 1 else 0
    digest = hmac.new(mac_key, page[start: PAGE_SIZE - HMAC_SIZE], hashlib.sha512)
    digest.update(struct.pack("<I", page_number))
    if not hmac.compare_digest(digest.digest(), page[PAGE_SIZE - HMAC_SIZE:]):
        raise ValueError(f"HMAC verification failed on page {page_number}")


def decrypt_to_temp(source: Path, destination: Path, key_hex: str) -> Path:
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise ValueError("Database key must be 32 bytes")
    size = source.stat().st_size
    if size < PAGE_SIZE or size % PAGE_SIZE:
        raise ValueError("Encrypted database size is not a positive multiple of 4096")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent))
    temp_path = Path(temp_name)
    try:
        with source.open("rb") as source_handle, os.fdopen(fd, "wb") as output_handle:
            first = source_handle.read(PAGE_SIZE)
            salt = first[:16]
            mac = hmac_key(key, salt)
            source_handle.seek(0)
            for page_number in range(1, size // PAGE_SIZE + 1):
                page = source_handle.read(PAGE_SIZE)
                if len(page) != PAGE_SIZE:
                    raise ValueError("Source changed or became truncated during refresh")
                verify_page(page, page_number, mac)
                encrypted_start = 16 if page_number == 1 else 0
                encrypted_end = PAGE_SIZE - RESERVE_SIZE
                iv = page[encrypted_end: encrypted_end + IV_SIZE]
                decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(page[encrypted_start:encrypted_end])
                output = bytearray(PAGE_SIZE)
                if page_number == 1:
                    output[:16] = SQLITE_HEADER
                    output[16:16 + len(decrypted)] = decrypted
                    output[16:18] = struct.pack(">H", PAGE_SIZE)
                else:
                    output[:len(decrypted)] = decrypted
                output_handle.write(output)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        return temp_path
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def validate_sqlite(path: Path) -> dict[str, object]:
    uri = path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError(f"SQLite quick_check returned {integrity!r}")
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )]
    return {"table_count": len(tables), "quick_check": "ok"}


def audit_receipt(status: str, stage: str, mode: str, records: list[dict[str, object]], error: str | None = None) -> Path:
    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%S.%fZ")
    receipt = {
        "schema_version": 1,
        "run_id": run_id,
        "time": now.isoformat(),
        "status": status,
        "stage": stage,
        "mode": mode,
        "core_results": records,
        "error": redact_error(error),
        "privacy": {"contains_keys": False, "contains_chat_content": False, "contains_private_paths": False},
    }
    path = AUDIT_DIR / f"refresh-{run_id}.json"
    atomic_write_json(path, receipt)
    return path


def redact_error(error: str | None) -> str | None:
    if error is None:
        return None
    value = str(error)
    for private in (str(PRIVATE_ROOT), str(Path.home())):
        value = value.replace(private, "<private>")
        value = value.replace(private.replace("\\", "/"), "<private>")
    return value[:1000]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verified Windows WeChat vault refresh")
    parser.add_argument("--mode", choices=("full", "incremental"), default="incremental")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    ensure_private_tree()
    records: list[dict[str, object]] = []
    stage = "CONFIG"
    try:
        config = load_config()
        db_base = Path(str(config["db_base_path"]))
        secret = load_secret_json()
        keys = secret.get("keys", {})
        if not isinstance(keys, dict):
            raise RuntimeError("Encrypted key store is invalid")
        missing_keys = [rel for rel in CORE_DATABASES if rel not in keys]
        if missing_keys:
            raise RuntimeError("Missing core database keys: " + ", ".join(missing_keys))
        state = load_json(STATE_FILE, {})
        next_state = dict(state) if isinstance(state, dict) else {}
        stage = "REFRESH"
        for rel in CORE_DATABASES:
            source = db_base / Path(rel)
            destination = DECRYPTED_DIR / Path(rel)
            if not source.exists():
                raise RuntimeError(f"Missing core source database: {rel}")
            before = fingerprint(source, str(keys[rel]))
            unchanged = args.mode == "incremental" and destination.exists() and state.get(rel) == before
            if unchanged:
                validation = validate_sqlite(destination)
                records.append({"rel": rel, "status": "unchanged", **validation})
                continue
            if args.dry_run:
                records.append({"rel": rel, "status": "would_refresh"})
                continue
            temp_path = decrypt_to_temp(source, destination, str(keys[rel]))
            try:
                after = fingerprint(source, str(keys[rel]))
                if after != before:
                    raise RuntimeError(f"Source changed during refresh: {rel}")
                validation = validate_sqlite(temp_path)
                os.replace(temp_path, destination)
                next_state[rel] = after
                records.append({"rel": rel, "status": "ok", **validation})
            finally:
                temp_path.unlink(missing_ok=True)
        allowed = {"ok", "unchanged", "would_refresh" if args.dry_run else "ok"}
        if any(record["status"] not in allowed for record in records) or len(records) != len(CORE_DATABASES):
            raise RuntimeError("Core database refresh gate failed")
        stage = "FRESHNESS"
        if not args.dry_run:
            for rel in CORE_DATABASES:
                current = fingerprint(db_base / Path(rel), str(keys[rel]))
                if next_state.get(rel) != current:
                    raise RuntimeError(f"STALE_VAULT: fingerprint mismatch for {rel}")
            atomic_write_json(STATE_FILE, next_state)
        manifest = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": args.mode,
            "dry_run": args.dry_run,
            "status": "DRY_RUN_OK" if args.dry_run else "VERIFIED_REFRESH",
            "records": records,
            "decrypted_dir": public_path_label(DECRYPTED_DIR),
            "privacy": {"contains_plaintext_wechat_data": not args.dry_run, "do_not_sync_or_share": True},
        }
        if not args.dry_run:
            atomic_write_json(MANIFEST_DIR / f"decrypt-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json", manifest)
        receipt = audit_receipt(manifest["status"], "COMPLETE", args.mode, records)
        print(json.dumps({**manifest, "audit": public_path_label(receipt)}, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        receipt = audit_receipt("FAILED", stage, args.mode, records, f"{type(exc).__name__}: {exc}")
        print(json.dumps({
            "status": "FAILED", "stage": stage, "error": redact_error(str(exc)),
            "audit": public_path_label(receipt),
        }, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
