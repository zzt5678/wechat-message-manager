from __future__ import annotations

import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import patch

import capture_keys_macos


class _FakeScript:
    def __init__(self, events: list[str], behavior: str) -> None:
        self.events = events
        self.behavior = behavior
        self.callback = None

    def on(self, event: str, callback) -> None:
        self.events.append(f"script.on:{event}")
        self.callback = callback

    def load(self) -> None:
        self.events.append("script.load")
        if self.behavior == "load_error":
            raise RuntimeError("synthetic script load failure")
        if self.behavior == "ready":
            self.events.append("hook.ready")
            self.callback({"type": "send", "payload": {"type": "ready"}}, None)

    def unload(self) -> None:
        self.events.append("script.unload")


class _FakeSession:
    def __init__(self, events: list[str], behavior: str) -> None:
        self.events = events
        self.script = _FakeScript(events, behavior)

    def create_script(self, _source: str) -> _FakeScript:
        self.events.append("session.create_script")
        return self.script

    def detach(self) -> None:
        self.events.append("session.detach")


class _FakeDevice:
    def __init__(self, events: list[str], behavior: str, pid: int) -> None:
        self.events = events
        self.pid = pid
        self.session = _FakeSession(events, behavior)

    def spawn(self, _argv: list[str]) -> int:
        self.events.append(f"device.spawn:{self.pid}")
        return self.pid

    def attach(self, pid: int) -> _FakeSession:
        self.events.append(f"device.attach:{pid}")
        return self.session

    def resume(self, pid: int) -> None:
        self.events.append(f"device.resume:{pid}")

    def kill(self, pid: int) -> None:
        self.events.append(f"device.kill:{pid}")


class MacOSSpawnSequenceTests(unittest.TestCase):
    CORE = ("contact/contact.db",)
    PID = 43210
    KEY = "11" * 32

    def run_capture(self, behavior: str) -> tuple[int, list[str], str, str]:
        events: list[str] = []
        device = _FakeDevice(events, behavior, self.PID)

        def get_local_device() -> _FakeDevice:
            events.append("frida.get_local_device")
            return device

        def validate_copy_process(pid: int, _app: Path) -> Path:
            events.append(f"validate_copy_process:{pid}")
            return Path("/private/test-copy/Contents/MacOS/WeChat")

        def require_exclusive_copy(pid: int | None = None) -> None:
            events.append(f"require_exclusive_copy:{pid}")

        output = io.StringIO()
        error = io.StringIO()
        fake_frida = SimpleNamespace(get_local_device=get_local_device)
        argv = [
            "capture_keys_macos.py",
            "--execute",
            "--i-understand-frida-hook",
            "--spawn-signed-copy",
            "--signed-copy",
            "/private/test-copy/WeChat.app",
            "--duration",
            "10",
        ]
        patches = [
            patch.dict(sys.modules, {"frida": fake_frida}),
            patch.object(sys, "argv", argv),
            patch.object(capture_keys_macos, "require_supported_platform"),
            patch.object(
                capture_keys_macos,
                "validate_signed_copy",
                return_value=Path("/private/test-copy/Contents/MacOS/WeChat"),
            ),
            patch.object(
                capture_keys_macos,
                "validate_copy_process",
                side_effect=validate_copy_process,
            ),
            patch.object(
                capture_keys_macos,
                "require_exclusive_copy",
                side_effect=require_exclusive_copy,
            ),
            patch.object(
                capture_keys_macos,
                "load_config",
                return_value={"db_base_path": "/private/test-db", "account_tag": "test"},
            ),
            patch.object(
                capture_keys_macos,
                "configured_core_databases",
                return_value=self.CORE,
            ),
            patch.object(
                capture_keys_macos,
                "pages",
                return_value={self.CORE[0]: b"page"},
            ),
            patch.object(
                capture_keys_macos,
                "verified_existing",
                return_value={self.CORE[0]: self.KEY},
            ),
            patch.object(capture_keys_macos, "save_secret_json"),
            patch.object(
                capture_keys_macos,
                "load_secret_json",
                return_value={"account_tag": "test", "keys": {self.CORE[0]: self.KEY}},
            ),
        ]
        if behavior == "not_ready":
            patches.append(
                patch.object(capture_keys_macos.time, "monotonic", side_effect=[0.0, 6.0])
            )

        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(error))
            for context in patches:
                stack.enter_context(context)
            result = capture_keys_macos.main()
        return result, events, output.getvalue(), error.getvalue()

    def test_spawn_is_validated_and_hook_is_ready_before_resume(self) -> None:
        result, events, _output, error = self.run_capture("ready")
        self.assertEqual(result, 0, error)
        expected_order = [
            f"device.spawn:{self.PID}",
            f"validate_copy_process:{self.PID}",
            f"require_exclusive_copy:{self.PID}",
            f"device.attach:{self.PID}",
            "session.create_script",
            "script.on:message",
            "script.load",
            "hook.ready",
            f"device.resume:{self.PID}",
        ]
        self.assertEqual(
            [event for event in events if event in expected_order],
            expected_order,
        )
        self.assertNotIn(f"device.kill:{self.PID}", events)

    def test_not_ready_kills_only_new_spawn_without_resume(self) -> None:
        result, events, _output, error = self.run_capture("not_ready")
        self.assertEqual(result, 5)
        self.assertIn("Frida hook did not report ready", error)
        self.assertNotIn(f"device.resume:{self.PID}", events)
        self.assertEqual(
            [event for event in events if event.startswith("device.kill:")],
            [f"device.kill:{self.PID}"],
        )

    def test_load_failure_kills_only_new_spawn_without_resume(self) -> None:
        result, events, _output, error = self.run_capture("load_error")
        self.assertEqual(result, 5)
        self.assertIn("synthetic script load failure", error)
        self.assertNotIn(f"device.resume:{self.PID}", events)
        self.assertEqual(
            [event for event in events if event.startswith("device.kill:")],
            [f"device.kill:{self.PID}"],
        )


if __name__ == "__main__":
    unittest.main()
