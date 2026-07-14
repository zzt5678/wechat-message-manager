from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wintypes
import json
import os
from pathlib import Path
from typing import Any

from manager_config import KEYS_FILE, atomic_write_bytes


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


CRYPTPROTECT_UI_FORBIDDEN = 0x1
_ENTROPY = b"wechat-message-manager-v1"
_LEGACY_ENTROPY = b"codex-wechat-vault-v1"


def _blob(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _crypt(data: bytes, protect: bool, entropy_value: bytes = _ENTROPY) -> bytes:
    if os.name != "nt":
        raise RuntimeError("DPAPI storage is only available on Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    source, source_buffer = _blob(data)
    entropy, entropy_buffer = _blob(entropy_value)
    destination = DATA_BLOB()
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(source), "Codex WeChat Vault", ctypes.byref(entropy), None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(destination),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(source), None, ctypes.byref(entropy), None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(destination),
        )
    # Keep ctypes buffers alive until the Windows call has returned.
    _ = source_buffer, entropy_buffer
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))


def save_secret_json(value: dict[str, Any], path: Path = KEYS_FILE) -> None:
    plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    protected = _crypt(plaintext, True)
    envelope = b"CWV1\n" + base64.b64encode(protected) + b"\n"
    atomic_write_bytes(path, envelope)


def load_secret_json(path: Path = KEYS_FILE) -> dict[str, Any]:
    if not path.exists():
        return {}
    envelope = path.read_bytes().splitlines()
    if len(envelope) != 2 or envelope[0] != b"CWV1":
        raise RuntimeError("Unknown encrypted key-file format")
    protected = base64.b64decode(envelope[1])
    last_error: OSError | None = None
    plaintext: bytes | None = None
    for entropy in (_ENTROPY, _LEGACY_ENTROPY):
        try:
            plaintext = _crypt(protected, False, entropy)
            break
        except OSError as exc:
            last_error = exc
    if plaintext is None:
        if last_error is not None:
            raise last_error
        raise RuntimeError("Unable to decrypt the protected key store")
    value = json.loads(plaintext.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Encrypted key file does not contain an object")
    return value
