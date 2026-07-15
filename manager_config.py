from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import platform
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator


PROJECT_DIR = Path(__file__).resolve().parent
TOOL_VERSION = "0.1.0-rc1"


def platform_support() -> dict[str, object]:
    """Describe the narrow platform boundary promised by this release."""
    architecture = platform.machine().casefold()
    python_bits = struct.calcsize("P") * 8
    windows_build: int | None = None
    if sys.platform == "win32":
        try:
            windows_build = int(sys.getwindowsversion().build)
        except (AttributeError, ValueError):
            windows_build = 0
        supported = (
            python_bits == 64 and architecture in {"amd64", "x86_64"}
            and windows_build >= 22_000
        )
        stop_reason = None if supported else "WINDOWS_11_X64_PYTHON_REQUIRED"
        platform_name = "windows"
    elif sys.platform == "darwin":
        supported = python_bits == 64 and architecture in {"arm64", "aarch64"}
        stop_reason = None if supported else "MACOS_APPLE_SILICON_PYTHON_REQUIRED"
        platform_name = "macos"
    else:
        supported = False
        stop_reason = "SUPPORTED_PLATFORM_REQUIRED"
        platform_name = sys.platform
    return {
        "supported": supported,
        "platform": platform_name,
        "architecture": architecture or "unknown",
        "python_bits": python_bits,
        "windows_build": windows_build,
        "stop_reason": stop_reason,
    }


def require_supported_platform(expected: str | None = None) -> dict[str, object]:
    value = platform_support()
    if expected is not None and value["platform"] != expected:
        raise RuntimeError("SUPPORTED_PLATFORM_REQUIRED")
    if not value["supported"]:
        raise RuntimeError(str(value["stop_reason"]))
    return value


def default_private_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
        preferred = base / "WechatMessageManager"
        legacy = base / "CodexWechatVault"
        # Existing installations keep their original private vault. Fresh
        # installations use the neutral public project name.
        if legacy.exists() and not preferred.exists():
            return legacy
        return preferred
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return base / "WechatMessageManager"


PRIVATE_ROOT = Path(os.environ.get("WECHAT_MANAGER_VAULT", default_private_root())).resolve()
CONFIG_FILE = PRIVATE_ROOT / "config.json"
KEYS_FILE = PRIVATE_ROOT / "secrets" / (
    "database-keys.dpapi" if os.name == "nt" else "database-keys.keychain"
)
DECRYPTED_DIR = PRIVATE_ROOT / "decrypted" / "current"
STATE_FILE = PRIVATE_ROOT / "state" / "decrypt-state.json"
MANIFEST_DIR = PRIVATE_ROOT / "manifests"
AUDIT_DIR = PRIVATE_ROOT / "audit"
EXPORTS_DIR = PRIVATE_ROOT / "exports"

# Schema-1 installations used a fixed four-shard list. Keep it only as a
# backwards-compatibility fallback for an existing private config. New
# configurations persist the databases actually present for the selected
# account, because WeChat creates a variable number of message shards.
CORE_DATABASES = (
    "contact/contact.db",
    "session/session.db",
    "message/message_0.db",
    "message/message_1.db",
    "message/message_2.db",
    "message/message_3.db",
    "message/message_resource.db",
)

REQUIRED_DATABASES = (
    "contact/contact.db",
    "session/session.db",
    "message/message_resource.db",
)
MESSAGE_SHARD_PATTERN = re.compile(r"message/message_(\d+)\.db\Z")


def discover_core_databases(db_base: Path) -> tuple[str, ...]:
    """Return the required databases and every numbered message shard present."""
    shards: list[tuple[int, str]] = []
    message_dir = db_base / "message"
    if message_dir.is_dir():
        for path in message_dir.glob("message_*.db"):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(db_base).as_posix()
            match = MESSAGE_SHARD_PATTERN.fullmatch(rel)
            if match:
                shards.append((int(match.group(1)), rel))
    shards.sort(key=lambda item: (item[0], item[1]))
    return (
        REQUIRED_DATABASES[0],
        REQUIRED_DATABASES[1],
        *(rel for _, rel in shards),
        REQUIRED_DATABASES[2],
    )


def validate_core_databases(value: object) -> tuple[str, ...]:
    """Validate a persisted database manifest without accepting arbitrary paths."""
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise RuntimeError("Private config has an invalid core database manifest")
    databases = tuple(value)
    if len(databases) != len(set(databases)):
        raise RuntimeError("Private config has duplicate core databases")
    if not all(rel in databases for rel in REQUIRED_DATABASES):
        raise RuntimeError("Private config is missing a required database")
    shards = [rel for rel in databases if MESSAGE_SHARD_PATTERN.fullmatch(rel)]
    if not shards:
        raise RuntimeError("Private config does not contain a numbered message shard")
    allowed = set(REQUIRED_DATABASES) | set(shards)
    if set(databases) != allowed:
        raise RuntimeError("Private config contains an unexpected database path")
    def shard_number(rel: str) -> int:
        match = MESSAGE_SHARD_PATTERN.fullmatch(rel)
        if match is None:  # Kept defensive even though ``shards`` is filtered above.
            raise RuntimeError("Private config contains an unexpected database path")
        return int(match.group(1))

    expected = (
        REQUIRED_DATABASES[0],
        REQUIRED_DATABASES[1],
        *sorted(shards, key=lambda rel: (shard_number(rel), rel)),
        REQUIRED_DATABASES[2],
    )
    if databases != expected:
        raise RuntimeError("Private config core database manifest is not canonical")
    return databases


def configured_core_databases(config: dict[str, Any], *, verify_source: bool = False) -> tuple[str, ...]:
    """Resolve the managed database set and optionally detect shard drift."""
    if "core_databases" in config:
        databases = validate_core_databases(config["core_databases"])
    else:
        # Existing schema-1 Windows vaults were verified against this exact
        # seven-database set. Re-running preflight --configure migrates them to
        # the dynamic manifest without weakening their current safety gate.
        databases = CORE_DATABASES
    if verify_source:
        db_base = Path(str(config.get("db_base_path", ""))).expanduser()
        discovered = discover_core_databases(db_base)
        missing_required = [
            rel for rel in REQUIRED_DATABASES
            if not (db_base / rel).is_file() or (db_base / rel).is_symlink()
        ]
        shards = [rel for rel in discovered if MESSAGE_SHARD_PATTERN.fullmatch(rel)]
        if missing_required or not shards:
            raise RuntimeError("CORE_DATABASE_MANIFEST_INVALID: required source databases are missing")
        if databases != discovered:
            raise RuntimeError("CORE_DATABASE_MANIFEST_CHANGED: run preflight --configure again")
    return databases


def wechat_process_count() -> int:
    if sys.platform == "darwin":
        completed = subprocess.run(
            ["pgrep", "-x", "WeChat"], capture_output=True, text=True, timeout=10, check=False,
        )
        if completed.returncode not in {0, 1}:
            raise RuntimeError("WECHAT_PROCESS_CHECK_FAILED")
        return len([value for value in completed.stdout.split() if value.isdigit()])
    if os.name == "nt":
        completed = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/NH"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("WECHAT_PROCESS_CHECK_FAILED")
        return completed.stdout.casefold().count("weixin.exe")
    return 0


def require_wechat_stopped() -> None:
    if wechat_process_count() > 0:
        raise RuntimeError("WECHAT_MUST_BE_STOPPED: exit WeChat manually before refresh or query")


def ensure_private_tree() -> None:
    for path in (
        PRIVATE_ROOT, KEYS_FILE.parent, DECRYPTED_DIR.parent, DECRYPTED_DIR,
        STATE_FILE.parent, MANIFEST_DIR, AUDIT_DIR, EXPORTS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(path, 0o700)


@contextmanager
def operation_lock(path: Path) -> Iterator[None]:
    """Serialize vault mutations and queries so freshness cannot race refresh."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RuntimeError("MANAGER_OPERATION_LOCK_FAILED") from exc
    with os.fdopen(fd, "r+b") as handle:
        if os.name != "nt":
            os.chmod(path, 0o600)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("MANAGER_OPERATION_IN_PROGRESS") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
    """Return a stable opaque label instead of a private absolute path."""
    return f"private:{account_tag(path)}"


def redact_private_text(error: object, extra_paths: tuple[Path, ...] = ()) -> str:
    """Redact user and vault paths from CLI errors before they reach logs or models."""
    value = str(error)
    paths = [Path.home(), PRIVATE_ROOT, *extra_paths]
    try:
        config = load_config()
        configured = config.get("db_base_path")
        if configured:
            paths.append(Path(str(configured)))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        pass
    for path in paths:
        private = str(path.expanduser())
        if not private:
            continue
        for spelling in {private, private.replace("\\", "/"), private.replace("/", "\\")}:
            if os.name == "nt":
                value = re.sub(re.escape(spelling), "<private>", value, flags=re.IGNORECASE)
            else:
                value = value.replace(spelling, "<private>")
    return value[:1000]
