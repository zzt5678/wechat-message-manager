from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent


def default_private_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return base / ("CodexWechatVault" if os.name == "nt" else "WechatMessageManager")


PRIVATE_ROOT = Path(os.environ.get("WECHAT_MANAGER_VAULT", default_private_root())).resolve()
CONFIG_FILE = PRIVATE_ROOT / "config.json"
KEYS_FILE = PRIVATE_ROOT / "secrets" / "database-keys.dpapi"
DECRYPTED_DIR = PRIVATE_ROOT / "decrypted" / "current"
STATE_FILE = PRIVATE_ROOT / "state" / "decrypt-state.json"
MANIFEST_DIR = PRIVATE_ROOT / "manifests"
AUDIT_DIR = PRIVATE_ROOT / "audit"
EXPORTS_DIR = PRIVATE_ROOT / "exports"

CORE_DATABASES = (
    "contact/contact.db",
    "session/session.db",
    "message/message_0.db",
    "message/message_1.db",
    "message/message_2.db",
    "message/message_3.db",
    "message/message_resource.db",
)


def ensure_private_tree() -> None:
    for path in (PRIVATE_ROOT, KEYS_FILE.parent, DECRYPTED_DIR, STATE_FILE.parent, MANIFEST_DIR, AUDIT_DIR, EXPORTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return {} if default is None else default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_config() -> dict[str, Any]:
    config = load_json(CONFIG_FILE, {})
    if not isinstance(config, dict):
        raise RuntimeError("Private config is not a JSON object")
    return config


def account_tag(path: Path) -> str:
    return hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:12]


def public_path_label(path: Path) -> str:
    """Return a stable non-reversible label instead of a private absolute path."""
    return f"private:{account_tag(path)}"
