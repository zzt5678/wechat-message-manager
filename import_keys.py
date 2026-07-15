from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys

from manager_config import (
    KEYS_FILE, TOOL_VERSION, configured_core_databases, load_config, public_path_label,
    redact_private_text, require_supported_platform,
)
from secret_store import load_secret_json, save_secret_json


PAGE_SIZE = 4096


def verify_key(key: bytes, page: bytes) -> bool:
    salt = page[:16]
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)
    digest = hmac.new(mac_key, page[16: PAGE_SIZE - 64], hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(digest.digest(), page[PAGE_SIZE - 64:])


def load_key_map(path: Path) -> dict[str, str]:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Import file exceeds the 1 MiB safety limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and isinstance(value.get("keys"), dict):
        value = value["keys"]
    if not isinstance(value, dict):
        raise ValueError("Import file must be a JSON object or contain a keys object")
    result: dict[str, str] = {}
    for rel, encoded in value.items():
        if not isinstance(rel, str) or not isinstance(encoded, str):
            continue
        try:
            key = bytes.fromhex(encoded)
        except ValueError:
            continue
        if len(key) == 32:
            result[rel.replace("\\", "/")] = key.hex()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Import database keys without printing them")
    parser.add_argument("--file", required=True, type=Path, help="local JSON key map")
    parser.add_argument("--delete-source", action="store_true", help="delete the plaintext JSON after verified import")
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
    source = args.file.expanduser().resolve()
    if not source.is_file():
        print("Import file does not exist", file=sys.stderr)
        return 2
    try:
        config = load_config()
        if not config.get("db_base_path"):
            raise RuntimeError("CONFIGURATION_REQUIRED: run preflight --configure first")
        core_databases = configured_core_databases(config, verify_source=True)
        db_base = Path(str(config["db_base_path"]))
        supplied = load_key_map(source)
        verified: dict[str, str] = {}
        for rel in core_databases:
            encoded = supplied.get(rel)
            if encoded is None:
                continue
            database = db_base / Path(rel)
            if not database.is_file():
                continue
            with database.open("rb") as handle:
                page = handle.read(PAGE_SIZE)
            if len(page) == PAGE_SIZE and verify_key(bytes.fromhex(encoded), page):
                verified[rel] = encoded
        if not all(rel in verified for rel in core_databases):
            raise RuntimeError("Imported keys did not validate every core database")
        protected_value = {
            "schema_version": 2,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "account_tag": config.get("account_tag"),
            "source": "verified-manual-import",
            "keys": verified,
        }
        save_secret_json(protected_value)
        readback = load_secret_json()
        if readback.get("account_tag") != protected_value["account_tag"] or readback.get("keys") != verified:
            raise RuntimeError("Protected key-store readback did not match; import source was retained")
        if args.delete_source:
            source.unlink()
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "VERIFIED_KEY_IMPORT",
            "validated_core_database_count": len(core_databases),
            "validated_database_count": len(verified),
            "source_deleted": args.delete_source,
            "keys_file": public_path_label(KEYS_FILE),
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "FAILED",
            "error": redact_private_text(exc, (source,)),
        }, ensure_ascii=False, indent=2), file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
