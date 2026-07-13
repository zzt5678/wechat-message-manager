from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys

from manager_config import CORE_DATABASES, load_config, public_path_label, KEYS_FILE
from secret_store import save_secret_json


PAGE_SIZE = 4096


def verify_key(key: bytes, page: bytes) -> bool:
    salt = page[:16]
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)
    digest = hmac.new(mac_key, page[16: PAGE_SIZE - 64], hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(digest.digest(), page[PAGE_SIZE - 64:])


def load_key_map(path: Path) -> dict[str, str]:
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
    source = args.file.expanduser().resolve()
    if not source.is_file():
        print("Import file does not exist", file=sys.stderr)
        return 2
    try:
        config = load_config()
        db_base = Path(str(config["db_base_path"]))
        supplied = load_key_map(source)
        verified: dict[str, str] = {}
        for rel, encoded in supplied.items():
            database = db_base / Path(rel)
            if not database.is_file():
                continue
            with database.open("rb") as handle:
                page = handle.read(PAGE_SIZE)
            if len(page) == PAGE_SIZE and verify_key(bytes.fromhex(encoded), page):
                verified[rel] = encoded
        if not all(rel in verified for rel in CORE_DATABASES):
            raise RuntimeError("Imported keys did not validate every core database")
        save_secret_json({
            "schema_version": 2,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "account_tag": config.get("account_tag"),
            "source": "verified-manual-import",
            "keys": verified,
        })
        if args.delete_source:
            source.unlink()
        print(json.dumps({
            "status": "VERIFIED_KEY_IMPORT",
            "validated_core_database_count": len(CORE_DATABASES),
            "validated_database_count": len(verified),
            "source_deleted": args.delete_source,
            "keys_file": public_path_label(KEYS_FILE),
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)[:500]}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
