from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wintypes
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
from typing import Iterable

from manager_config import CONFIG_FILE, CORE_DATABASES, load_config, public_path_label, KEYS_FILE
from secret_store import save_secret_json


PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
MAX_ADDRESS = 0x7FFFFFFFFFFF
READ_CHUNK_SIZE = 16 * 1024 * 1024

# WeChat 4.x keeps a masked account passphrase behind a small private-memory
# descriptor. A candidate is never trusted until keys derived from it validate
# every core database's page-1 HMAC.
DESCRIPTOR_PATTERN = re.compile(br"(.{6}\x00{10}\x20\x00{7}\x2f\x00{7})", re.DOTALL)
DLL_MASK_PATTERN = re.compile(
    br"\x48\xBA(.{8}).{3,8}?\x48\xBA(.{8}).{3,8}?"
    br"\x48\xBA(.{8}).{3,8}?\x48\xBA(.{8}).{3,8}?\x48\x85\xC0",
    re.DOTALL,
)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def process_info() -> dict[str, object]:
    script = r'''
$p = Get-Process Weixin -ErrorAction Stop | Select-Object -First 1
$m = $p.Modules | Where-Object ModuleName -eq 'Weixin.dll' | Select-Object -First 1
if (-not $m) { throw 'Weixin.dll is not loaded' }
$s = Get-AuthenticodeSignature -LiteralPath $m.FileName
[pscustomobject]@{
  path = $m.FileName
  version = $m.FileVersionInfo.FileVersion
  signature = $s.Status.ToString()
  signer = $s.SignerCertificate.Subject
} | ConvertTo-Json -Compress
'''
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Unable to inspect the running Weixin process")
    value = json.loads(completed.stdout)
    signer = str(value.get("signer", ""))
    if value.get("signature") != "Valid" or "Tencent" not in signer:
        raise RuntimeError("The loaded Weixin.dll does not have a valid Tencent signature")
    return value


def get_pids() -> list[int]:
    completed = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    pids: list[int] = []
    for line in completed.stdout.splitlines():
        match = re.match(r'^"Weixin\.exe","(\d+)"', line.strip(), re.IGNORECASE)
        if match:
            pids.append(int(match.group(1)))
    return pids


def collect_pages(db_base: Path) -> dict[str, bytes]:
    pages: dict[str, bytes] = {}
    for path in db_base.rglob("*.db"):
        if not path.is_file() or path.name.endswith(("-wal", "-shm")):
            continue
        try:
            with path.open("rb") as handle:
                page = handle.read(PAGE_SIZE)
        except OSError:
            continue
        if len(page) != PAGE_SIZE:
            continue
        rel = path.relative_to(db_base).as_posix()
        pages[rel] = page
    missing = [rel for rel in CORE_DATABASES if rel not in pages]
    if missing:
        raise RuntimeError("One or more core databases are missing or unreadable")
    return pages


def find_dll_masks(path: Path) -> set[bytes]:
    data = path.read_bytes()
    return {b"".join(match.groups()) for match in DLL_MASK_PATTERN.finditer(data)}


def is_potential_key(value: bytes) -> bool:
    return len(value) == KEY_SIZE and len(set(value)) >= 15 and sum(32 <= b <= 126 for b in value) <= 24


def derive_enc_key(passphrase: bytes, page1: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", passphrase, page1[:SALT_SIZE], 256000, dklen=KEY_SIZE)


def verify_enc_key(key: bytes, page1: bytes) -> bool:
    salt = page1[:SALT_SIZE]
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=KEY_SIZE)
    digest = hmac.new(mac_key, page1[SALT_SIZE: PAGE_SIZE - 64], hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(digest.digest(), page1[PAGE_SIZE - 64: PAGE_SIZE])


def read_exact(kernel32, handle, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)):
        return b""
    return buffer.raw[:read.value] if read.value == size else b""


def scan_process(pid: int) -> tuple[set[bytes], dict[str, int]]:
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return set(), {"opened": 0, "bytes_read": 0, "markers": 0}
    candidates: set[bytes] = set()
    bytes_read = 0
    markers = 0
    try:
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while address < MAX_ADDRESS:
            queried = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not queried:
                break
            base, size = int(mbi.BaseAddress or 0), int(mbi.RegionSize)
            readable = (
                mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            )
            if readable and 0 < size <= 2 * 1024 * 1024 * 1024:
                offset, overlap = 0, b""
                while offset < size:
                    amount = min(READ_CHUNK_SIZE, size - offset)
                    buffer = ctypes.create_string_buffer(amount)
                    read = ctypes.c_size_t()
                    ok = kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base + offset), buffer, amount, ctypes.byref(read)
                    )
                    if ok and read.value:
                        bytes_read += int(read.value)
                        block = overlap + buffer.raw[:read.value]
                        for match in DESCRIPTOR_PATTERN.finditer(block):
                            markers += 1
                            pointer = struct.unpack_from("<Q", match.group(1), 0)[0]
                            if 0 < pointer <= MAX_ADDRESS:
                                value = read_exact(kernel32, handle, pointer, KEY_SIZE)
                                if is_potential_key(value):
                                    candidates.add(value)
                        overlap = block[-64:]
                    else:
                        overlap = b""
                    offset += amount
            next_address = base + max(size, 1)
            if next_address <= address:
                break
            address = next_address
    finally:
        kernel32.CloseHandle(handle)
    return candidates, {"opened": 1, "bytes_read": bytes_read, "markers": markers}


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def recover(raw_candidates: Iterable[bytes], masks: Iterable[bytes], pages: dict[str, bytes]) -> tuple[bytes, dict[str, str]] | None:
    probe = pages[CORE_DATABASES[0]]
    for raw in raw_candidates:
        for mask in masks:
            passphrase = xor_bytes(raw, mask)
            if not verify_enc_key(derive_enc_key(passphrase, probe), probe):
                continue
            keys: dict[str, str] = {}
            for rel, page in pages.items():
                key = derive_enc_key(passphrase, page)
                if verify_enc_key(key, page):
                    keys[rel] = key.hex()
            if all(rel in keys for rel in CORE_DATABASES):
                return passphrase, keys
    return None


def plan(config: dict[str, object]) -> dict[str, object]:
    return {
        "status": "READY_FOR_KEY_CAPTURE_APPROVAL",
        "action": "CURRENT_VERSION_READ_ONLY_PROCESS_MEMORY_SCAN",
        "process": "Weixin.exe",
        "wechat_version": config.get("wechat_version", "detected-at-runtime"),
        "requires_administrator": False,
        "may_require_elevation_if_process_access_is_denied": True,
        "closes_or_restarts_wechat": False,
        "injects_or_hooks": False,
        "writes_process_memory": False,
        "reads_signed_weixin_dll": True,
        "validation": "all core database page-1 HMACs",
        "keys_at_rest": "Windows DPAPI, current user only",
        "keys_file": public_path_label(KEYS_FILE),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Current-version read-only Windows WeChat 4.x key recovery")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--i-understand-read-process-memory", action="store_true")
    args = parser.parse_args()
    if sys.platform != "win32":
        print("Windows only", file=sys.stderr)
        return 2
    if not CONFIG_FILE.exists():
        print("Run preflight --configure first", file=sys.stderr)
        return 2
    config = load_config()
    if not args.execute:
        print(json.dumps(plan(config), ensure_ascii=False, indent=2))
        return 0
    if not args.i_understand_read_process_memory:
        print("Refusing capture: explicit acknowledgement flag is missing", file=sys.stderr)
        return 2

    started = time.monotonic()
    result: dict[str, object] = {
        "status": "FAILED", "checked_at": utc_now(), "read_only_process_access": True,
        "process_memory_written": False, "hook_installed": False, "wechat_restarted": False,
        "secret_output": False,
    }
    try:
        info = process_info()
        pages = collect_pages(Path(str(config["db_base_path"])))
        masks = find_dll_masks(Path(str(info["path"])))
        if not masks:
            raise RuntimeError("No compatible mask pattern was found in the signed Weixin.dll")
        pids = get_pids()
        if not pids:
            raise RuntimeError("Weixin.exe is not running")
        candidates: set[bytes] = set()
        opened = bytes_read = markers = 0
        for pid in pids:
            found, stats = scan_process(pid)
            candidates.update(found)
            opened += stats["opened"]
            bytes_read += stats["bytes_read"]
            markers += stats["markers"]
        recovered = recover(candidates, masks, pages)
        if recovered is None:
            raise RuntimeError("No candidate passed every core database HMAC gate")
        passphrase, keys = recovered
        save_secret_json({
            "schema_version": 2,
            "captured_at": utc_now(),
            "account_tag": config.get("account_tag"),
            "source": "windows-v4-read-only-current-version",
            "passphrase": passphrase.hex(),
            "keys": keys,
        })
        result.update({
            "status": "VERIFIED_CURRENT_VERSION_READ_ONLY_RECOVERY",
            "wechat_version": info.get("version", "unknown"),
            "process_count": len(pids), "opened_processes": opened,
            "bytes_read": bytes_read, "memory_markers": markers,
            "unique_candidate_count": len(candidates), "dll_mask_candidate_count": len(masks),
            "validated_core_database_count": len(CORE_DATABASES),
            "validated_database_count": len(keys), "keys_file": public_path_label(KEYS_FILE),
        })
    except Exception as exc:
        result.update({"error_type": type(exc).__name__, "error": str(exc)[:500]})
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "VERIFIED_CURRENT_VERSION_READ_ONLY_RECOVERY" else 5


if __name__ == "__main__":
    raise SystemExit(main())
