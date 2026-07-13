from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

from import_keys import verify_key
from manager_config import CORE_DATABASES, KEYS_FILE, load_config, public_path_label
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
        "status": "READY_FOR_MACOS_HOOK_APPROVAL",
        "action": "ATTACH_FRIDA_TO_USER_PREPARED_AD_HOC_SIGNED_COPY",
        "modifies_original_wechat": False,
        "starts_or_controls_wechat": False,
        "ui_automation": False,
        "hook_installed_in_copy_process": True,
        "requires_separate_signed_copy": True,
        "validation": "all core database page-1 HMACs",
        "keys_at_rest": "macOS Keychain",
    }


def pages() -> dict[str, bytes]:
    root = Path(str(load_config()["db_base_path"]))
    result: dict[str, bytes] = {}
    for path in root.rglob("*.db"):
        if path.is_file():
            with path.open("rb") as handle:
                page = handle.read(4096)
            if len(page) == 4096:
                result[path.relative_to(root).as_posix()] = page
    if not all(rel in result for rel in CORE_DATABASES):
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


def validate_copy_process(pid: int, app: Path) -> None:
    original = Path("/Applications/WeChat.app").resolve()
    app = app.expanduser().resolve()
    if app == original or not (app / "Contents/MacOS/WeChat").is_file():
        raise RuntimeError("--signed-copy must point to a separate WeChat.app copy")
    checked = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", str(app)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if checked.returncode != 0:
        raise RuntimeError("The separate WeChat copy does not pass codesign verification")
    command = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, timeout=10, check=False
    ).stdout.strip()
    if str(app / "Contents/MacOS/WeChat") not in command:
        raise RuntimeError("PID does not belong to the declared signed copy")


def main() -> int:
    parser = argparse.ArgumentParser(description="Opt-in macOS WeChat key capture from a signed copy")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--i-understand-frida-hook", action="store_true")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--signed-copy", type=Path)
    parser.add_argument("--duration", type=int, default=240)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(plan(), ensure_ascii=False, indent=2))
        return 0
    if sys.platform != "darwin":
        print("macOS only", file=sys.stderr)
        return 2
    if not args.i_understand_frida_hook or not args.pid or not args.signed_copy:
        print("Explicit hook acknowledgement, PID, and signed-copy path are required", file=sys.stderr)
        return 2
    try:
        import frida
    except ImportError:
        print("Install the macOS requirements first", file=sys.stderr)
        return 2
    try:
        validate_copy_process(args.pid, args.signed_copy)
        targets = pages()
        found = verified_existing(targets)
        state = {"ready": False, "error": None, "candidate_count": 0}

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

        session = frida.attach(args.pid)
        script = session.create_script(HOOK)
        try:
            script.on("message", on_message)
            script.load()
            deadline = time.monotonic() + max(10, min(args.duration, 600))
            while time.monotonic() < deadline and not all(rel in found for rel in CORE_DATABASES):
                if state["error"]:
                    raise RuntimeError(str(state["error"]))
                time.sleep(0.25)
        finally:
            try:
                script.unload()
            finally:
                session.detach()
        if not all(rel in found for rel in CORE_DATABASES):
            raise RuntimeError("Capture ended before every core database key was verified")
        save_secret_json({
            "schema_version": 2,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "account_tag": load_config().get("account_tag"),
            "source": "macos-opt-in-frida-signed-copy",
            "keys": found,
        })
        print(json.dumps({
            "status": "VERIFIED_MACOS_SIGNED_COPY_CAPTURE",
            "hook_ready": state["ready"],
            "candidate_count": state["candidate_count"],
            "validated_core_database_count": len(CORE_DATABASES),
            "validated_database_count": len(found),
            "keys_file": public_path_label(KEYS_FILE),
            "secret_output": False,
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)[:500]}, ensure_ascii=False), file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
