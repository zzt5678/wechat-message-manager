from __future__ import annotations

import json
import os
import sys
from typing import Any

from manager_config import KEYS_FILE, atomic_write_json, load_config


SERVICE = "wechat-message-manager"


def _account() -> str:
    value = load_config().get("account_tag", "default")
    return str(value)


def _native_macos_keyring():
    try:
        import keyring
    except ImportError as exc:
        raise RuntimeError("Install requirements.txt to enable macOS Keychain storage") from exc
    backend = keyring.get_keyring()
    backend_type = type(backend)
    if backend_type.__module__ != "keyring.backends.macOS" or backend_type.__name__ != "Keyring":
        raise RuntimeError("Refusing non-native keyring backend; macOS Keychain is required")
    return keyring


def save_secret_json(value: dict[str, Any]) -> None:
    if os.name == "nt":
        from dpapi_store import save_secret_json as save_dpapi

        save_dpapi(value)
        return
    if sys.platform != "darwin":
        raise RuntimeError("Secret storage is supported only on Windows and macOS")
    keyring = _native_macos_keyring()
    keyring.set_password(SERVICE, _account(), json.dumps(value, separators=(",", ":")))
    atomic_write_json(KEYS_FILE, {"schema_version": 1, "backend": "macos-keychain", "account": _account()})
    os.chmod(KEYS_FILE, 0o600)


def load_secret_json() -> dict[str, Any]:
    if os.name == "nt":
        from dpapi_store import load_secret_json as load_dpapi

        return load_dpapi()
    if sys.platform != "darwin":
        return {}
    keyring = _native_macos_keyring()
    encoded = keyring.get_password(SERVICE, _account())
    if not encoded:
        return {}
    value = json.loads(encoded)
    if not isinstance(value, dict):
        raise RuntimeError("Keychain entry is not a JSON object")
    return value
