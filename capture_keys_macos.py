from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import time

from import_keys import verify_key
from manager_config import (
    KEYS_FILE, TOOL_VERSION, configured_core_databases, load_config, public_path_label,
    redact_private_text, require_supported_platform,
)
from secret_store import load_secret_json, save_secret_json


HOOK = r'''
const target = Module.findGlobalExportByName('CCKeyDerivationPBKDF');
if (target === null) {
  send({type: 'error', code: 'PBKDF_EXPORT_NOT_FOUND'});
} else {
  Interceptor.attach(target, {
    onEnter(args) {
      this.output = args[7];
      this.length = args[8].toInt32();
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0 || this.length !== 32) return;
      const bytes = new Uint8Array(this.output.readByteArray(32));
      let encoded = '';
      for (let i = 0; i < bytes.length; i++) encoded += bytes[i].toString(16).padStart(2, '0');
      send({type: 'candidate', value: encoded});
    }
  });
  send({type: 'ready'});
}
'''


def plan() -> dict[str, object]:
    return {
        "tool_version": TOOL_VERSION,
        "status": "READY_FOR_MACOS_HOOK_APPROVAL",
        "action": "SPAWN_OR_ATTACH_FRIDA_TO_USER_PREPARED_AD_HOC_SIGNED_COPY",
        "modifies_original_wechat": False,
        "starts_original_wechat": False,
        "spawn_mode_starts_signed_copy_after_approval": True,
        "spawn_setup_failure_may_stop_only_new_copy": True,
        "ui_automation": False,
        "hook_installed_in_copy_process": True,
        "requires_separate_signed_copy": True,
        "validation": "all core database page-1 HMACs",
        "keys_at_rest": "macOS Keychain",
    }


def pages(config: dict[str, object], core_databases: tuple[str, ...]) -> dict[str, bytes]:
    root = Path(str(config["db_base_path"]))
    result: dict[str, bytes] = {}
    for rel in core_databases:
        path = root / rel
        if path.is_file():
            with path.open("rb") as handle:
                page = handle.read(4096)
            if len(page) == 4096:
                result[rel] = page
    if not all(rel in result for rel in core_databases):
        raise RuntimeError("One or more core databases are missing")
    return result


def verified_existing(targets: dict[str, bytes]) -> dict[str, str]:
    stored = load_secret_json().get("keys", {})
    if not isinstance(stored, dict):
        return {}
    result = {}
    for rel, encoded in stored.items():
        try:
            key = bytes.fromhex(str(encoded))
        except ValueError:
            continue
        if rel in targets and len(key) == 32 and verify_key(key, targets[rel]):
            result[rel] = key.hex()
    return result


def match_candidate(candidate: bytes, targets: dict[str, bytes], found: dict[str, str]) -> int:
    if len(candidate) != 32:
        return 0
    added = 0
    for rel, page in targets.items():
        if rel not in found and verify_key(candidate, page):
            found[rel] = candidate.hex()
            added += 1
    return added


def validate_signed_copy(app: Path) -> Path:
    original = Path("/Applications/WeChat.app").resolve()
    app = app.expanduser().resolve()
    binary = app / "Contents/MacOS/WeChat"
    if app == original or app.is_relative_to(original) or not binary.is_file():
        raise RuntimeError("--signed-copy must point to a separate WeChat.app copy")
    with (app / "Contents/Info.plist").open("rb") as handle:
        bundle = plistlib.load(handle)
    if bundle.get("CFBundleIdentifier") != "com.tencent.xinWeChat":
        raise RuntimeError("The signed copy has an unexpected bundle identifier")
    checked = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", "--all-architectures", str(app)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if checked.returncode != 0:
        raise RuntimeError("The separate WeChat copy does not pass codesign verification")
    return binary.resolve()


def process_executable(pid: int) -> Path:
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libproc.proc_pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    length = libproc.proc_pidpath(pid, buffer, len(buffer))
    if length <= 0:
        raise RuntimeError("Unable to resolve the declared PID executable")
    return Path(buffer.value.decode("utf-8")).resolve()


def validate_copy_process(pid: int, app: Path) -> Path:
    binary = validate_signed_copy(app)
    if process_executable(pid) != binary:
        raise RuntimeError("PID does not belong to the declared signed copy")
    return binary


def running_wechat_pids() -> set[int]:
    completed = subprocess.run(
        ["pgrep", "-x", "WeChat"], capture_output=True, text=True, timeout=10, check=False,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError("WECHAT_PROCESS_CHECK_FAILED")
    return {int(value) for value in completed.stdout.split() if value.isdigit()}


def require_exclusive_copy(pid: int | None = None) -> None:
    running = running_wechat_pids()
    expected = set() if pid is None else {pid}
    if running != expected:
        raise RuntimeError("Exit every other WeChat process before signed-copy capture")


def main() -> int:
    parser = argparse.ArgumentParser(description="Opt-in macOS WeChat key capture from a signed copy")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--i-understand-frida-hook", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--pid", type=int, help="attach to an already running signed copy")
    mode.add_argument(
        "--spawn-signed-copy", action="store_true",
        help="spawn the signed copy suspended, install the hook, then resume it",
    )
    parser.add_argument("--signed-copy", type=Path)
    parser.add_argument("--duration", type=int, default=240)
    args = parser.parse_args()
    try:
        require_supported_platform("macos")
    except RuntimeError as exc:
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "FAILED",
            "error": str(exc),
        }, ensure_ascii=False), file=sys.stderr)
        return 2
    if not args.execute:
        print(json.dumps(plan(), ensure_ascii=False, indent=2))
        return 0
    if (
        not args.i_understand_frida_hook or not args.signed_copy
        or (args.pid is None and not args.spawn_signed_copy)
    ):
        print("Explicit hook acknowledgement, one capture mode, and signed-copy path are required", file=sys.stderr)
        return 2
    try:
        import frida
    except ImportError:
        print("Install the macOS requirements first", file=sys.stderr)
        return 2
    try:
        binary = validate_signed_copy(args.signed_copy)
        config = load_config()
        if not config.get("db_base_path"):
            raise RuntimeError("CONFIGURATION_REQUIRED: run preflight --configure first")
        core_databases = configured_core_databases(config, verify_source=True)
        targets = pages(config, core_databases)
        found = verified_existing(targets)
        state = {"ready": False, "error": None, "candidate_count": 0}
        device = None
        spawned_pid: int | None = None

        def on_message(message, data) -> None:
            payload = message.get("payload", {}) if message.get("type") == "send" else {}
            kind = payload.get("type") if isinstance(payload, dict) else None
            if kind == "ready":
                state["ready"] = True
            elif kind == "error":
                state["error"] = str(payload.get("code", "HOOK_ERROR"))
            elif kind == "candidate":
                try:
                    candidate = bytes.fromhex(str(payload.get("value", "")))
                except ValueError:
                    return
                if len(candidate) != 32:
                    return
                state["candidate_count"] += 1
                match_candidate(candidate, targets, found)

        session = None
        script = None
        resumed = False
        try:
            if args.spawn_signed_copy:
                require_exclusive_copy()
                device = frida.get_local_device()
                spawned_pid = int(device.spawn([str(binary)]))
                validate_copy_process(spawned_pid, args.signed_copy)
                require_exclusive_copy(spawned_pid)
                session = device.attach(spawned_pid)
            else:
                validate_copy_process(args.pid, args.signed_copy)
                require_exclusive_copy(args.pid)
                session = frida.attach(args.pid)
            script = session.create_script(HOOK)
            script.on("message", on_message)
            script.load()
            ready_deadline = time.monotonic() + 5
            while not state["ready"] and not state["error"] and time.monotonic() < ready_deadline:
                time.sleep(0.05)
            if state["error"]:
                raise RuntimeError(str(state["error"]))
            if not state["ready"]:
                raise RuntimeError("Frida hook did not report ready")
            if spawned_pid is not None:
                device.resume(spawned_pid)
                resumed = True
            deadline = time.monotonic() + max(10, min(args.duration, 600))
            while time.monotonic() < deadline and not all(rel in found for rel in core_databases):
                if state["error"]:
                    raise RuntimeError(str(state["error"]))
                time.sleep(0.25)
        finally:
            try:
                if script is not None:
                    script.unload()
            finally:
                try:
                    if session is not None:
                        session.detach()
                finally:
                    if spawned_pid is not None and not resumed:
                        device.kill(spawned_pid)
        if not all(rel in found for rel in core_databases):
            raise RuntimeError("Capture ended before every core database key was verified")
        protected_value = {
            "schema_version": 2,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "account_tag": config.get("account_tag"),
            "source": "macos-opt-in-frida-signed-copy",
            "keys": found,
        }
        save_secret_json(protected_value)
        readback = load_secret_json()
        if readback.get("account_tag") != protected_value["account_tag"] or readback.get("keys") != found:
            raise RuntimeError("Protected key-store readback did not match the captured keys")
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "VERIFIED_MACOS_SIGNED_COPY_CAPTURE",
            "hook_ready": state["ready"],
            "capture_mode": "spawn-signed-copy" if args.spawn_signed_copy else "attach-existing-copy",
            "candidate_count": state["candidate_count"],
            "validated_core_database_count": len(core_databases),
            "validated_database_count": len(found),
            "keys_file": public_path_label(KEYS_FILE),
            "secret_output": False,
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        extra = (args.signed_copy,) if args.signed_copy else ()
        print(json.dumps({
            "tool_version": TOOL_VERSION,
            "status": "FAILED",
            "error": redact_private_text(exc, extra),
        }, ensure_ascii=False), file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
