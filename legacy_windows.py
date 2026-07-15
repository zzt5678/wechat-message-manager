from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Iterable

from capture_keys_windows import (
    KEY_SIZE,
    collect_pages,
    get_pids,
    process_info,
    recover,
    scan_process,
    utc_now,
)
from manager_config import (
    CONFIG_FILE,
    CORE_DATABASES,
    PRIVATE_ROOT,
    atomic_write_json,
    load_config,
    load_json,
    public_path_label,
)
from secret_store import save_secret_json


LEGACY_RUNTIME_VERSION = "4.1.9.57"
LEGACY_INSTALLER_VERSION = "4.1.9.1000"
LEGACY_INSTALLER_URL = "https://dldir1v6.qq.com/weixin/Universal/Windows/WeChatWin_4.1.9.exe"
LEGACY_INSTALLER_SIZE = 234_965_064
LEGACY_INSTALLER_SHA256 = "8f43225b7388742a9797d31960bf19d6b0902ea58bf1a85b6d8b95d0b71877ed"
ZERO_MASK = bytes(KEY_SIZE)

EMERGENCY_ROOT = PRIVATE_ROOT / "emergency-windows-4.1.9"
INSTALLER_PATH = EMERGENCY_ROOT / "installers" / "WeChatWin_4.1.9.exe"
PAYLOAD_ROOT = EMERGENCY_ROOT / "payload" / LEGACY_RUNTIME_VERSION
CURRENT_BACKUP_ROOT = EMERGENCY_ROOT / "current-launcher"
STATE_FILE = EMERGENCY_ROOT / "state.json"
SNAPSHOT_ROOT = EMERGENCY_ROOT / "database-snapshots"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def signature_info(path: Path) -> dict[str, object]:
    script = r'''
$ErrorActionPreference = 'Stop'
$p = $env:WECHAT_MANAGER_SIGNATURE_PATH
$f = Get-Item -LiteralPath $p
$s = Get-AuthenticodeSignature -LiteralPath $p
[pscustomobject]@{
  length = $f.Length
  file_version = $f.VersionInfo.FileVersion
  product_version = $f.VersionInfo.ProductVersion
  signature = $s.Status.ToString()
  signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
} | ConvertTo-Json -Compress
'''
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "WECHAT_MANAGER_SIGNATURE_PATH": str(path)},
    )
    if completed.returncode != 0:
        raise RuntimeError("Unable to verify the Windows Authenticode signature")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Authenticode verification returned invalid metadata") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Authenticode verification returned invalid metadata")
    return value


def require_tencent_signature(path: Path, *, exact_version: str | None = None) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("The expected signed program file is missing")
    value = signature_info(path)
    if value.get("signature") != "Valid" or "tencent" not in str(value.get("signer", "")).casefold():
        raise RuntimeError("The program file does not have a valid Tencent Authenticode signature")
    if exact_version is not None and str(value.get("file_version", "")) != exact_version:
        raise RuntimeError("The signed program file has an unexpected version")
    return value


def verify_legacy_installer(path: Path = INSTALLER_PATH) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("The pinned legacy installer is missing")
    if path.stat().st_size != LEGACY_INSTALLER_SIZE:
        raise RuntimeError("The legacy installer size does not match the pinned release")
    digest = sha256_file(path)
    if digest != LEGACY_INSTALLER_SHA256:
        raise RuntimeError("The legacy installer SHA-256 does not match the pinned release")
    metadata = require_tencent_signature(path, exact_version=LEGACY_INSTALLER_VERSION)
    return {
        "status": "VERIFIED_PINNED_TENCENT_LEGACY_INSTALLER",
        "version": LEGACY_RUNTIME_VERSION,
        "installer_version": metadata.get("file_version"),
        "bytes": LEGACY_INSTALLER_SIZE,
        "sha256": LEGACY_INSTALLER_SHA256,
        "origin": urllib.parse.urlparse(LEGACY_INSTALLER_URL).hostname,
        "installer": public_path_label(path),
    }


def plan() -> dict[str, object]:
    return {
        "status": "READY_FOR_EXPLICIT_WINDOWS_LEGACY_FALLBACK",
        "default_path": False,
        "use_only_after_current_capture_incompatibility": True,
        "legacy_version": LEGACY_RUNTIME_VERSION,
        "download_origin": urllib.parse.urlparse(LEGACY_INSTALLER_URL).hostname,
        "download_bytes": LEGACY_INSTALLER_SIZE,
        "pinned_sha256": LEGACY_INSTALLER_SHA256,
        "requires_7zip_for_private_extraction": True,
        "installer_is_committed_to_repository": False,
        "silent_install_or_uninstall": False,
        "preserves_current_version_directory": True,
        "backs_up_current_launcher": True,
        "snapshots_core_databases_before_switch": True,
        "requires_separate_switch_approval": True,
        "requires_separate_process_memory_approval": True,
        "requires_separate_restore_approval": True,
        "validation": "Tencent Authenticode + pinned SHA-256 + all core database HMACs",
    }


def download_installer() -> dict[str, object]:
    INSTALLER_PATH.parent.mkdir(parents=True, exist_ok=True)
    if INSTALLER_PATH.exists():
        return {**verify_legacy_installer(INSTALLER_PATH), "downloaded": False}

    if shutil.disk_usage(INSTALLER_PATH.parent).free < LEGACY_INSTALLER_SIZE + 512 * 1024 * 1024:
        raise RuntimeError("Insufficient free space for the pinned legacy installer")

    parsed = urllib.parse.urlparse(LEGACY_INSTALLER_URL)
    if parsed.scheme != "https" or parsed.hostname != "dldir1v6.qq.com":
        raise RuntimeError("The pinned legacy installer origin is not allowed")

    fd, temp_name = tempfile.mkstemp(prefix=".wechat-legacy-", suffix=".download", dir=INSTALLER_PATH.parent)
    os.close(fd)
    temporary = Path(temp_name)
    try:
        request = urllib.request.Request(LEGACY_INSTALLER_URL, headers={"User-Agent": "WechatMessageManager/1"})
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "dldir1v6.qq.com" or final.path != parsed.path:
                raise RuntimeError("The legacy installer download redirected outside the pinned Tencent origin")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) != LEGACY_INSTALLER_SIZE:
                raise RuntimeError("The Tencent origin returned an unexpected installer size")
            total = 0
            while True:
                block = response.read(4 * 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > LEGACY_INSTALLER_SIZE:
                    raise RuntimeError("The Tencent origin exceeded the pinned installer size")
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        verify_legacy_installer(temporary)
        os.replace(temporary, INSTALLER_PATH)
        return {**verify_legacy_installer(INSTALLER_PATH), "downloaded": True}
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def find_7zip() -> Path | None:
    candidates: list[Path] = []
    found = shutil.which("7z.exe") or shutil.which("7z")
    if found:
        candidates.append(Path(found))
    for name in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(name)
        if base:
            candidates.append(Path(base) / "7-Zip" / "7z.exe")
    # Some developer environments provide the standalone binary here. It is
    # never downloaded or committed by this project.
    candidates.append(Path("C:/MinGW/bin/7z.exe"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(path.resolve()), str(root.resolve())]) == str(root.resolve())
    except (OSError, ValueError):
        return False


def remove_private_tree(path: Path) -> None:
    if not is_within(path, EMERGENCY_ROOT) or path.resolve() == EMERGENCY_ROOT.resolve():
        raise RuntimeError("Refusing to remove an unexpected directory")
    if path.exists():
        shutil.rmtree(path)


def remove_installed_legacy_tree(path: Path, install_root: Path) -> None:
    expected = (install_root / LEGACY_RUNTIME_VERSION).resolve()
    if path.resolve() != expected or expected.parent != install_root.resolve() or path.is_symlink():
        raise RuntimeError("Refusing to remove an unexpected program directory")
    if path.exists():
        shutil.rmtree(path)


def run_7zip(executable: Path, archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    completed = subprocess.run(
        [str(executable), "x", str(archive), f"-o{destination}", "-y"],
        capture_output=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("7-Zip could not extract the verified Tencent package")


def verify_payload(root: Path) -> dict[str, Path]:
    launcher = root / "Weixin.exe"
    version_dir = root / LEGACY_RUNTIME_VERSION
    dll = version_dir / "Weixin.dll"
    require_tencent_signature(launcher, exact_version=LEGACY_RUNTIME_VERSION)
    require_tencent_signature(dll, exact_version=LEGACY_RUNTIME_VERSION)
    return {"launcher": launcher, "version_dir": version_dir, "dll": dll}


def extract_payload(installer: Path = INSTALLER_PATH) -> dict[str, Path]:
    if PAYLOAD_ROOT.exists():
        return verify_payload(PAYLOAD_ROOT)
    seven_zip = find_7zip()
    if seven_zip is None:
        raise RuntimeError("7-Zip is required only for the emergency route; install it from 7-zip.org and retry")
    if shutil.disk_usage(EMERGENCY_ROOT).free < 2 * 1024 * 1024 * 1024:
        raise RuntimeError("At least 2 GiB free space is required to prepare the legacy payload")

    work = EMERGENCY_ROOT / f".extract-{os.getpid()}"
    outer = work / "outer"
    inner = work / "inner"
    if work.exists():
        remove_private_tree(work)
    try:
        work.mkdir(parents=True)
        run_7zip(seven_zip, installer, outer)
        embedded = outer / "install.7z"
        if not embedded.is_file():
            raise RuntimeError("The pinned Tencent installer did not contain the expected payload")
        run_7zip(seven_zip, embedded, inner)
        verify_payload(inner)
        PAYLOAD_ROOT.parent.mkdir(parents=True, exist_ok=True)
        if PAYLOAD_ROOT.exists():
            raise RuntimeError("The private legacy payload appeared concurrently; refusing to overwrite it")
        os.replace(inner, PAYLOAD_ROOT)
        return verify_payload(PAYLOAD_ROOT)
    finally:
        if work.exists():
            remove_private_tree(work)


def load_state() -> dict[str, object]:
    value = load_json(STATE_FILE, {})
    if not isinstance(value, dict):
        raise RuntimeError("The private emergency state is invalid")
    return value


def save_state(value: dict[str, object]) -> None:
    atomic_write_json(STATE_FILE, value)


def prepare_fallback() -> dict[str, object]:
    verify_legacy_installer()
    existing = load_state()
    if existing.get("status") in {"SWITCHED_TO_LEGACY", "LEGACY_KEYS_CAPTURED", "RESTORED_PENDING_VERIFICATION"}:
        raise RuntimeError("An emergency version transition is already active; restore it before preparing again")

    info = process_info()
    current_version = str(info.get("version", ""))
    if not current_version or current_version == LEGACY_RUNTIME_VERSION:
        raise RuntimeError("Prepare must run while the signed current WeChat version is open")
    current_dll = Path(str(info["path"])).resolve()
    current_version_dir = current_dll.parent
    install_root = current_version_dir.parent
    current_launcher = install_root / "Weixin.exe"
    require_tencent_signature(current_dll, exact_version=current_version)
    require_tencent_signature(current_launcher, exact_version=current_version)

    payload = extract_payload()
    current_launcher_backup = CURRENT_BACKUP_ROOT / current_version / "Weixin.exe"
    current_launcher_backup.parent.mkdir(parents=True, exist_ok=True)
    current_launcher_hash = sha256_file(current_launcher)
    if current_launcher_backup.exists():
        if sha256_file(current_launcher_backup) != current_launcher_hash:
            raise RuntimeError("The existing private current-launcher backup belongs to another version")
    else:
        shutil.copy2(current_launcher, current_launcher_backup)
    require_tencent_signature(current_launcher_backup, exact_version=current_version)

    config = load_config()
    state: dict[str, object] = {
        "schema_version": 1,
        "status": "PREPARED",
        "prepared_at": utc_now(),
        "current_version": current_version,
        "install_root": str(install_root),
        "current_launcher": str(current_launcher),
        "current_launcher_sha256": current_launcher_hash,
        "current_launcher_backup": str(current_launcher_backup),
        "current_dll": str(current_dll),
        "current_dll_sha256": sha256_file(current_dll),
        "db_base_path": str(config["db_base_path"]),
        "legacy_launcher": str(payload["launcher"]),
        "legacy_version_dir": str(payload["version_dir"]),
        "legacy_launcher_sha256": sha256_file(payload["launcher"]),
        "legacy_dll_sha256": sha256_file(payload["dll"]),
    }
    save_state(state)
    return {
        "status": "PREPARED_SIGNED_LEGACY_FALLBACK",
        "current_version": current_version,
        "legacy_version": LEGACY_RUNTIME_VERSION,
        "current_launcher_backup": public_path_label(current_launcher_backup),
        "legacy_payload": public_path_label(PAYLOAD_ROOT),
        "application_modified": False,
        "next": "Exit WeChat manually, then run legacy-switch with its explicit acknowledgement flag",
    }


def require_admin() -> None:
    if not bool(ctypes.windll.shell32.IsUserAnAdmin()):
        raise RuntimeError("This version-switch step requires an Administrator PowerShell")


def require_wechat_stopped() -> None:
    if get_pids():
        raise RuntimeError("Exit WeChat manually before changing signed program files")


def verify_prepared_current(state: dict[str, object]) -> tuple[Path, Path, Path]:
    install_root = Path(str(state["install_root"])).resolve()
    launcher = Path(str(state["current_launcher"])).resolve()
    backup = Path(str(state["current_launcher_backup"])).resolve()
    current_dll = Path(str(state["current_dll"])).resolve()
    if launcher.parent != install_root or current_dll.parent.parent != install_root:
        raise RuntimeError("The recorded WeChat program layout is no longer consistent")
    if not is_within(backup, CURRENT_BACKUP_ROOT):
        raise RuntimeError("The recorded current-launcher backup is outside the private emergency directory")
    version = str(state["current_version"])
    require_tencent_signature(launcher, exact_version=version)
    require_tencent_signature(backup, exact_version=version)
    require_tencent_signature(current_dll, exact_version=version)
    if sha256_file(launcher) != state["current_launcher_sha256"]:
        raise RuntimeError("The installed current launcher changed after preparation")
    if sha256_file(backup) != state["current_launcher_sha256"]:
        raise RuntimeError("The private current-launcher backup failed its hash check")
    if sha256_file(current_dll) != state["current_dll_sha256"]:
        raise RuntimeError("The preserved current-version DLL changed after preparation")
    return install_root, launcher, backup


def copy_stable(source: Path, destination: Path) -> tuple[int, str]:
    before = sha256_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    after = sha256_file(source)
    copied = sha256_file(destination)
    if before != after or before != copied:
        raise RuntimeError("A source database changed while creating the emergency snapshot")
    return source.stat().st_size, before


def snapshot_core_databases(db_base: Path) -> tuple[Path, list[dict[str, object]]]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    temporary = SNAPSHOT_ROOT / f".{stamp}-{os.getpid()}.tmp"
    destination = SNAPSHOT_ROOT / stamp
    if destination.exists() or temporary.exists():
        raise RuntimeError("The private database snapshot destination already exists")
    manifest: list[dict[str, object]] = []
    try:
        temporary.mkdir(parents=True)
        for rel in CORE_DATABASES:
            source = db_base / Path(rel)
            if not source.is_file():
                raise RuntimeError("One or more core databases are missing before the version switch")
            sources = [source]
            for suffix in ("-wal", "-shm"):
                companion = source.with_name(source.name + suffix)
                if companion.is_file():
                    sources.append(companion)
            for item in sources:
                relative = item.relative_to(db_base)
                size, digest = copy_stable(item, temporary / relative)
                manifest.append({"relative": relative.as_posix(), "bytes": size, "sha256": digest})
        atomic_write_json(temporary / "manifest.json", {"created_at": utc_now(), "files": manifest})
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temporary, destination)
        return destination, manifest
    finally:
        if temporary.exists():
            remove_private_tree(temporary)


def switch_to_legacy() -> dict[str, object]:
    require_admin()
    require_wechat_stopped()
    state = load_state()
    if state.get("status") != "PREPARED":
        raise RuntimeError("Run legacy-prepare successfully before switching versions")
    install_root, launcher, backup = verify_prepared_current(state)
    payload = verify_payload(PAYLOAD_ROOT)
    if sha256_file(payload["launcher"]) != state["legacy_launcher_sha256"]:
        raise RuntimeError("The private legacy launcher changed after preparation")
    if sha256_file(payload["dll"]) != state["legacy_dll_sha256"]:
        raise RuntimeError("The private legacy DLL changed after preparation")

    target_version_dir = (install_root / LEGACY_RUNTIME_VERSION).resolve()
    if target_version_dir.parent != install_root or target_version_dir.exists():
        raise RuntimeError("The legacy target version directory already exists or is unexpected")

    snapshot, manifest = snapshot_core_databases(Path(str(state["db_base_path"])).resolve())
    temporary_launcher = install_root / ".wechat-message-manager-legacy.tmp"
    if temporary_launcher.exists():
        raise RuntimeError("A previous temporary launcher file still exists")
    try:
        shutil.copytree(payload["version_dir"], target_version_dir)
        require_tencent_signature(target_version_dir / "Weixin.dll", exact_version=LEGACY_RUNTIME_VERSION)
        shutil.copy2(payload["launcher"], temporary_launcher)
        require_tencent_signature(temporary_launcher, exact_version=LEGACY_RUNTIME_VERSION)
        os.replace(temporary_launcher, launcher)
        require_tencent_signature(launcher, exact_version=LEGACY_RUNTIME_VERSION)
    except Exception:
        if temporary_launcher.exists():
            temporary_launcher.unlink()
        if backup.is_file():
            shutil.copy2(backup, launcher)
        if target_version_dir.exists():
            remove_installed_legacy_tree(target_version_dir, install_root)
        raise

    state.update({
        "status": "SWITCHED_TO_LEGACY",
        "switched_at": utc_now(),
        "snapshot": str(snapshot),
        "snapshot_file_count": len(manifest),
        "installed_legacy_version_dir": str(target_version_dir),
    })
    save_state(state)
    return {
        "status": "VERIFIED_TEMPORARY_LEGACY_SWITCH",
        "legacy_version": LEGACY_RUNTIME_VERSION,
        "current_version_directory_preserved": True,
        "core_snapshot_file_count": len(manifest),
        "database_snapshot": public_path_label(snapshot),
        "next": "Start WeChat manually, log in, then run legacy-capture after separate approval",
    }


def recover_legacy(raw_candidates: Iterable[bytes], pages: dict[str, bytes]):
    return recover(raw_candidates, [ZERO_MASK], pages)


def capture_legacy() -> dict[str, object]:
    if not CONFIG_FILE.exists():
        raise RuntimeError("Run preflight --configure first")
    state = load_state()
    if state.get("status") != "SWITCHED_TO_LEGACY":
        raise RuntimeError("The managed legacy switch is not active")
    info = process_info()
    if str(info.get("version")) != LEGACY_RUNTIME_VERSION:
        raise RuntimeError("Legacy capture only accepts the pinned signed WeChat 4.1.9.57 runtime")

    config = load_config()
    pages = collect_pages(Path(str(config["db_base_path"])))
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
    recovered = recover_legacy(candidates, pages)
    if recovered is None:
        raise RuntimeError("No direct 4.1.9 candidate passed every core database HMAC gate")
    passphrase, keys = recovered
    save_secret_json({
        "schema_version": 2,
        "captured_at": utc_now(),
        "account_tag": config.get("account_tag"),
        "source": "windows-v4-legacy-4.1.9-read-only",
        "passphrase": passphrase.hex(),
        "keys": keys,
    })
    state.update({"status": "LEGACY_KEYS_CAPTURED", "captured_at": utc_now()})
    save_state(state)
    return {
        "status": "VERIFIED_LEGACY_419_READ_ONLY_RECOVERY",
        "wechat_version": LEGACY_RUNTIME_VERSION,
        "read_only_process_access": True,
        "process_memory_written": False,
        "hook_installed": False,
        "secret_output": False,
        "process_count": len(pids),
        "opened_processes": opened,
        "bytes_read": bytes_read,
        "memory_markers": markers,
        "unique_candidate_count": len(candidates),
        "validated_core_database_count": len(CORE_DATABASES),
        "validated_database_count": len(keys),
        "next": "Exit WeChat manually, then restore the preserved current version",
    }


def restore_current() -> dict[str, object]:
    require_admin()
    require_wechat_stopped()
    state = load_state()
    if state.get("status") not in {"SWITCHED_TO_LEGACY", "LEGACY_KEYS_CAPTURED"}:
        raise RuntimeError("There is no active managed legacy switch to restore")
    install_root = Path(str(state["install_root"])).resolve()
    launcher = Path(str(state["current_launcher"])).resolve()
    backup = Path(str(state["current_launcher_backup"])).resolve()
    current_dll = Path(str(state["current_dll"])).resolve()
    if launcher.parent != install_root or current_dll.parent.parent != install_root:
        raise RuntimeError("The recorded WeChat program layout is no longer consistent")
    if not is_within(backup, CURRENT_BACKUP_ROOT):
        raise RuntimeError("The recorded current-launcher backup is outside the private emergency directory")
    version = str(state["current_version"])
    require_tencent_signature(backup, exact_version=version)
    require_tencent_signature(current_dll, exact_version=version)
    if sha256_file(backup) != state["current_launcher_sha256"]:
        raise RuntimeError("The private current-launcher backup failed its hash check")
    if sha256_file(current_dll) != state["current_dll_sha256"]:
        raise RuntimeError("The preserved current-version DLL failed its hash check")

    temporary = install_root / ".wechat-message-manager-restore.tmp"
    if temporary.exists():
        raise RuntimeError("A previous temporary restore file still exists")
    shutil.copy2(backup, temporary)
    try:
        require_tencent_signature(temporary, exact_version=version)
        os.replace(temporary, launcher)
    finally:
        if temporary.exists():
            temporary.unlink()
    require_tencent_signature(launcher, exact_version=version)
    if sha256_file(launcher) != state["current_launcher_sha256"]:
        raise RuntimeError("The restored current launcher failed its hash check")
    state.update({"status": "RESTORED_PENDING_VERIFICATION", "restored_at": utc_now()})
    save_state(state)
    return {
        "status": "RESTORED_CURRENT_LAUNCHER_PENDING_RUNTIME_VERIFICATION",
        "restored_version": version,
        "legacy_copy_retained_until_verified": True,
        "next": "Start WeChat manually, log in, then run legacy-verify-restored",
    }


def verify_restored() -> dict[str, object]:
    state = load_state()
    if state.get("status") != "RESTORED_PENDING_VERIFICATION":
        raise RuntimeError("Restore verification is not pending")
    info = process_info()
    expected_version = str(state["current_version"])
    dll = Path(str(info["path"])).resolve()
    expected_dll = Path(str(state["current_dll"])).resolve()
    if str(info.get("version")) != expected_version or dll != expected_dll:
        raise RuntimeError("The running WeChat process is not the preserved current version")
    if sha256_file(dll) != state["current_dll_sha256"]:
        raise RuntimeError("The running current-version DLL failed its hash check")
    state.update({"status": "RESTORED_CURRENT_VERSION", "verified_restored_at": utc_now()})
    save_state(state)
    return {
        "status": "VERIFIED_CURRENT_VERSION_RESTORED",
        "wechat_version": expected_version,
        "next": "Run refresh --mode full, then optionally remove the installed legacy copy",
    }


def cleanup_installed_legacy() -> dict[str, object]:
    require_admin()
    require_wechat_stopped()
    state = load_state()
    if state.get("status") != "RESTORED_CURRENT_VERSION":
        raise RuntimeError("Verify the restored current runtime before cleanup")
    install_root = Path(str(state["install_root"])).resolve()
    target = Path(str(state["installed_legacy_version_dir"])).resolve()
    if target != (install_root / LEGACY_RUNTIME_VERSION).resolve() or target.parent != install_root:
        raise RuntimeError("Refusing to remove an unexpected program directory")
    dll = target / "Weixin.dll"
    require_tencent_signature(dll, exact_version=LEGACY_RUNTIME_VERSION)
    if sha256_file(dll) != state["legacy_dll_sha256"]:
        raise RuntimeError("The installed legacy directory no longer matches the prepared payload")
    remove_installed_legacy_tree(target, install_root)
    state.update({"status": "LEGACY_COPY_CLEANED", "cleaned_at": utc_now()})
    save_state(state)
    return {
        "status": "VERIFIED_LEGACY_COPY_CLEANED",
        "current_version": state["current_version"],
        "private_installer_retained_for_future_emergency": True,
        "private_database_snapshot_retained": True,
    }


def print_result(operation) -> int:
    started = time.monotonic()
    try:
        result = operation()
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "status": "FAILED",
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "secret_output": False,
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }, ensure_ascii=False, indent=2))
        return 5


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicit Windows WeChat 4.1.9 emergency fallback")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan")
    download = subparsers.add_parser("download")
    download.add_argument("--i-understand-download-legacy-installer", action="store_true")
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--i-understand-prepare-private-backup", action="store_true")
    switch = subparsers.add_parser("switch")
    switch.add_argument("--i-understand-temporary-version-switch", action="store_true")
    capture = subparsers.add_parser("capture")
    capture.add_argument("--i-understand-read-process-memory", action="store_true")
    restore = subparsers.add_parser("restore")
    restore.add_argument("--i-understand-restore-current-version", action="store_true")
    subparsers.add_parser("verify-restored")
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--i-understand-remove-installed-legacy-copy", action="store_true")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Windows only", file=sys.stderr)
        return 2
    if args.command == "plan":
        print(json.dumps(plan(), ensure_ascii=False, indent=2))
        return 0
    gates = {
        "download": ("i_understand_download_legacy_installer", download_installer),
        "prepare": ("i_understand_prepare_private_backup", prepare_fallback),
        "switch": ("i_understand_temporary_version_switch", switch_to_legacy),
        "capture": ("i_understand_read_process_memory", capture_legacy),
        "restore": ("i_understand_restore_current_version", restore_current),
        "verify-restored": (None, verify_restored),
        "cleanup": ("i_understand_remove_installed_legacy_copy", cleanup_installed_legacy),
    }
    flag, operation = gates[args.command]
    if flag is not None and not getattr(args, flag):
        print("Refusing emergency action: the explicit acknowledgement flag is missing", file=sys.stderr)
        return 2
    return print_result(operation)


if __name__ == "__main__":
    raise SystemExit(main())
