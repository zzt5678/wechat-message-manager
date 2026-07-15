from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import venv
from contextlib import closing, redirect_stderr, redirect_stdout
from unittest.mock import patch

import capture_keys_macos
import capture_keys_windows
import import_keys
import manager_config
import preflight
import refresh_vault
import vault_query
from manager_config import (
    configured_core_databases,
    discover_core_databases,
    validate_core_databases,
)
from scripts.install_skill import install as install_skill


def core_paths(root: Path, shard_numbers: tuple[int, ...]) -> tuple[str, ...]:
    paths = (
        "contact/contact.db",
        "session/session.db",
        *(f"message/message_{number}.db" for number in shard_numbers),
        "message/message_resource.db",
    )
    for rel in paths:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * 4096)
    return paths


def authenticated_page(key: bytes, salt: bytes) -> bytes:
    page = bytearray(4096)
    page[:16] = salt
    page[16:-64] = bytes((index * 19 + 5) % 256 for index in range(16, 4096 - 64))
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)
    digest = hmac.new(mac_key, page[16:-64], hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    page[-64:] = digest.digest()
    return bytes(page)


class DynamicManifestTests(unittest.TestCase):
    def test_supported_platform_matrix_is_narrow(self) -> None:
        with (
            patch.object(manager_config.sys, "platform", "win32"),
            patch.object(manager_config.platform, "machine", return_value="AMD64"),
            patch.object(manager_config.struct, "calcsize", return_value=8),
            patch.object(manager_config.sys, "getwindowsversion", create=True, return_value=type("Win", (), {"build": 22631})()),
        ):
            self.assertTrue(manager_config.platform_support()["supported"])
        with (
            patch.object(manager_config.sys, "platform", "darwin"),
            patch.object(manager_config.platform, "machine", return_value="arm64"),
            patch.object(manager_config.struct, "calcsize", return_value=8),
        ):
            self.assertTrue(manager_config.platform_support()["supported"])
        for system, architecture, reason in (
            ("darwin", "x86_64", "MACOS_APPLE_SILICON_PYTHON_REQUIRED"),
            ("linux", "x86_64", "SUPPORTED_PLATFORM_REQUIRED"),
        ):
            with (
                self.subTest(system=system, architecture=architecture),
                patch.object(manager_config.sys, "platform", system),
                patch.object(manager_config.platform, "machine", return_value=architecture),
                patch.object(manager_config.struct, "calcsize", return_value=8),
            ):
                value = manager_config.platform_support()
                self.assertFalse(value["supported"])
                self.assertEqual(value["stop_reason"], reason)

        with (
            patch.object(manager_config.sys, "platform", "win32"),
            patch.object(manager_config.platform, "machine", return_value="AMD64"),
            patch.object(manager_config.struct, "calcsize", return_value=8),
            patch.object(manager_config.sys, "getwindowsversion", create=True, return_value=type("Win", (), {"build": 19045})()),
        ):
            self.assertEqual(
                manager_config.platform_support()["stop_reason"],
                "WINDOWS_11_X64_PYTHON_REQUIRED",
            )

    def test_preflight_unsupported_platform_stops_before_discovery(self) -> None:
        output = io.StringIO()
        with (
            patch.object(preflight, "platform_support", return_value={
                "supported": False, "platform": "linux", "architecture": "x86_64",
                "python_bits": 64, "stop_reason": "SUPPORTED_PLATFORM_REQUIRED",
            }),
            patch.object(preflight, "discover_db_storages") as discover,
            patch.object(sys, "argv", ["preflight.py"]),
            redirect_stdout(output),
        ):
            self.assertEqual(preflight.main(), 2)
        discover.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["stop_reason"], "SUPPORTED_PLATFORM_REQUIRED")

    def test_macos_capture_cli_stops_before_plan_on_unsupported_platform(self) -> None:
        error = io.StringIO()
        with (
            patch.object(
                capture_keys_macos, "require_supported_platform",
                side_effect=RuntimeError("MACOS_APPLE_SILICON_PYTHON_REQUIRED"),
            ),
            patch.object(capture_keys_macos, "plan") as capture_plan,
            patch.object(sys, "argv", ["capture_keys_macos.py"]),
            redirect_stderr(error),
        ):
            self.assertEqual(capture_keys_macos.main(), 2)
        capture_plan.assert_not_called()
        self.assertIn("MACOS_APPLE_SILICON_PYTHON_REQUIRED", error.getvalue())

    def test_data_commands_stop_before_private_access_on_unsupported_platform(self) -> None:
        cases = (
            (refresh_vault, ["refresh_vault.py", "--dry-run"], "ensure_private_tree"),
            (vault_query, ["vault_query.py", "status"], "operation_lock"),
            (import_keys, ["import_keys.py", "--file", "/private/keys.json"], "load_config"),
        )
        for module, argv, downstream_name in cases:
            with self.subTest(module=module.__name__):
                error = io.StringIO()
                with (
                    patch.object(
                        module, "require_supported_platform",
                        side_effect=RuntimeError("SUPPORTED_PLATFORM_REQUIRED"),
                    ),
                    patch.object(module, downstream_name) as downstream,
                    patch.object(sys, "argv", argv),
                    redirect_stderr(error),
                ):
                    self.assertEqual(module.main(), 2)
                downstream.assert_not_called()
                self.assertIn("SUPPORTED_PLATFORM_REQUIRED", error.getvalue())

    def test_discovers_variable_and_noncontiguous_message_shards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = core_paths(root, (0, 2, 5))
            (root / "message/message_resource_extra.db").write_bytes(b"ignored")
            self.assertEqual(discover_core_databases(root), expected)
            self.assertEqual(validate_core_databases(list(expected)), expected)

    def test_manifest_drift_is_a_hard_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = core_paths(root, (0, 1))
            config = {"db_base_path": str(root), "core_databases": list(original)}
            self.assertEqual(configured_core_databases(config, verify_source=True), original)
            (root / "message/message_4.db").write_bytes(b"x" * 4096)
            with self.assertRaisesRegex(RuntimeError, "CORE_DATABASE_MANIFEST_CHANGED"):
                configured_core_databases(config, verify_source=True)

    def test_manifest_rejects_unmanaged_paths_and_missing_shards(self) -> None:
        with self.assertRaises(RuntimeError):
            validate_core_databases([
                "contact/contact.db", "session/session.db", "message/message_resource.db",
            ])
        with self.assertRaises(RuntimeError):
            validate_core_databases([
                "contact/contact.db", "session/session.db", "message/message_0.db",
                "message/message_resource.db", "../../outside.db",
            ])

    def test_preflight_reports_dynamic_shards_and_transaction_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = core_paths(root, (0, 1))
            (root / "misc").mkdir()
            (root / "misc/internal_private_value.db").write_bytes(b"x" * 4096)
            (root / paths[2]).with_name("message_0.db-wal").write_bytes(b"pending")
            report = preflight.inspect(root)
            self.assertEqual(report["core_present"], list(paths))
            self.assertEqual(report["relative_databases"], list(paths))
            self.assertNotIn("internal_private_value", json.dumps(report))
            self.assertEqual(report["database_count"], len(paths) + 1)
            self.assertEqual(report["message_shard_count"], 2)
            self.assertEqual(report["nonempty_transaction_log_databases"], [paths[2]])

    def test_reconfigure_different_account_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = temp / "account" / "db_storage"
            paths = core_paths(source, (0,))
            config_file = temp / "vault/config.json"
            config_file.parent.mkdir(parents=True)
            config_file.write_text(json.dumps({
                "schema_version": 2,
                "db_base_path": str(temp / "old/db_storage"),
                "account_tag": "different-account",
                "core_databases": list(paths),
            }), encoding="utf-8")
            output = io.StringIO()
            with (
                patch.object(preflight, "CONFIG_FILE", config_file),
                patch.object(preflight, "KEYS_FILE", temp / "vault/secrets/key"),
                patch.object(preflight, "PRIVATE_ROOT", temp / "vault"),
                patch.object(preflight, "discover_db_storages", return_value=[source]),
                patch.object(preflight, "wechat_info", return_value={"version": "test"}),
                patch.object(preflight, "ensure_private_tree"),
                patch.object(sys, "argv", ["preflight.py", "--configure"]),
                redirect_stdout(output),
            ):
                self.assertEqual(preflight.main(), 2)
            self.assertEqual(json.loads(output.getvalue())["stop_reason"], "ACCOUNT_CHANGE_REQUIRES_NEW_VAULT")
            self.assertEqual(json.loads(config_file.read_text(encoding="utf-8"))["account_tag"], "different-account")


class FreshnessTests(unittest.TestCase):
    def test_refresh_and_query_require_wechat_to_be_stopped(self) -> None:
        with patch.object(manager_config, "wechat_process_count", return_value=1):
            with self.assertRaisesRegex(RuntimeError, "WECHAT_MUST_BE_STOPPED"):
                manager_config.require_wechat_stopped()

    def test_process_detection_failure_is_not_treated_as_stopped(self) -> None:
        completed = subprocess.CompletedProcess(["pgrep"], 2, stdout="", stderr="failed")
        with (
            patch.object(manager_config.sys, "platform", "darwin"),
            patch.object(manager_config.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(RuntimeError, "WECHAT_PROCESS_CHECK_FAILED"):
                manager_config.wechat_process_count()

    def test_vault_operations_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock_file = Path(directory) / "manager.lock"
            with manager_config.operation_lock(lock_file):
                with self.assertRaisesRegex(RuntimeError, "MANAGER_OPERATION_IN_PROGRESS"):
                    with manager_config.operation_lock(lock_file):
                        self.fail("nested operation unexpectedly acquired the lock")

    def test_fingerprint_tracks_wal_and_rollback_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.db"
            path.write_bytes(b"x" * 4096)
            clean = refresh_vault.fingerprint(path, "ab" * 32)
            self.assertEqual(clean["wal_bytes"], 0)
            self.assertEqual(clean["journal_bytes"], 0)
            path.with_name(path.name + "-wal").write_bytes(b"wal")
            path.with_name(path.name + "-journal").write_bytes(b"journal")
            pending = refresh_vault.fingerprint(path, "ab" * 32)
            self.assertEqual(pending["wal_bytes"], 3)
            self.assertEqual(pending["journal_bytes"], 7)
            with self.assertRaisesRegex(RuntimeError, "SOURCE_TRANSACTION_LOG_PRESENT_UNSUPPORTED"):
                refresh_vault.require_supported_source_snapshot(pending, "message/message_0.db")

    def test_query_rechecks_freshness_before_emitting(self) -> None:
        first = ({}, ("contact/contact.db",))
        stderr = io.StringIO()
        with (
            patch.object(vault_query, "freshness_gate", side_effect=[first, RuntimeError("changed")]),
            patch.object(vault_query, "sessions", return_value=[]),
            patch.object(vault_query, "emit") as emit,
            patch.object(sys, "argv", [
                "vault_query.py", "sessions", "--i-understand-message-content-output",
            ]),
            redirect_stderr(stderr),
        ):
            self.assertEqual(vault_query.main(), 2)
        emit.assert_not_called()


class OutputSafetyTests(unittest.TestCase):
    def test_content_commands_require_explicit_output_approval(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "MESSAGE_CONTENT_OUTPUT_APPROVAL_REQUIRED"):
            vault_query.require_content_output_approval("digest-source", False)
        vault_query.require_content_output_approval("digest-source", True)
        vault_query.require_content_output_approval("status", False)

    def test_controls_bidi_and_oversized_text_are_sanitized(self) -> None:
        stable_ids = "wxid_" + "private123" + " group123@" + "chatroom" + " gh_" + "private456"
        value = "safe\x1b[31m\u202eevil\nforged " + stable_ids + " " + "x" * 5000
        result = vault_query.safe_text(value, 100)
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\u202e", result)
        self.assertNotIn("\n", result)
        self.assertNotIn("private123", result)
        self.assertNotIn("group123", result)
        self.assertNotIn("private456", result)
        self.assertIn("[internal-id]", result)
        self.assertLessEqual(len(result), 100)
        self.assertTrue(result.endswith("[truncated]"))

    def test_nontext_xml_is_not_returned_as_message_body(self) -> None:
        result = vault_query.message_text({"local_type": 49, "message_content": "<appmsg>secret</appmsg>"})
        self.assertEqual(result, "[非文本消息 type=49]")

    def test_output_limits_are_disclosable_and_character_budget_is_bounded(self) -> None:
        limits = vault_query.output_limits()
        self.assertEqual(limits["per_message_chars_max"], 4_000)
        self.assertEqual(limits["history_messages_max"], 200)
        self.assertEqual(limits["digest_messages_max"], 1_000)
        self.assertEqual(limits["untrusted_text_chars_default"], 30_000)
        self.assertEqual(limits["untrusted_text_chars_max"], 120_000)
        self.assertEqual(vault_query.bounded_char_budget(0), 1)
        self.assertEqual(vault_query.bounded_char_budget(999_999), 120_000)

    def test_internal_username_never_becomes_a_public_display_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contact_path = root / "contact/contact.db"
            session_path = root / "session/session.db"
            contact_path.parent.mkdir(parents=True)
            session_path.parent.mkdir(parents=True)
            import sqlite3
            with closing(sqlite3.connect(contact_path)) as db:
                db.execute("CREATE TABLE contact (username TEXT, remark TEXT, nick_name TEXT)")
                db.execute("INSERT INTO contact VALUES ('private_user_identifier', '', '')")
                db.commit()
            with closing(sqlite3.connect(session_path)) as db:
                db.execute("CREATE TABLE SessionNoContactInfoTable (username TEXT, session_title TEXT)")
                db.execute(
                    "CREATE TABLE SessionTable (username TEXT, type INTEGER, unread_count INTEGER, "
                    "summary TEXT, last_timestamp INTEGER, is_hidden INTEGER, sort_timestamp INTEGER)"
                )
                db.execute(
                    "INSERT INTO SessionTable VALUES "
                    "('private_user_identifier', 1, 0, 'preview', 1700000000, 0, 1700000000)"
                )
                db.commit()
            with (
                patch.object(vault_query, "DECRYPTED_DIR", root),
                patch.object(vault_query, "load_secret_json", return_value={"keys": {"db": "key"}}),
            ):
                public = [vault_query.public_session(row) for row in vault_query.sessions()]
            self.assertNotIn("private_user_identifier", json.dumps(public, ensure_ascii=False))
            self.assertEqual(public[0]["name"], "[未命名会话]")

    def test_duplicate_display_names_can_use_opaque_session_tag(self) -> None:
        rows = [
            {"name": "同名", "_session_tag": "a" * 16},
            {"name": "同名", "_session_tag": "b" * 16},
        ]
        with patch.object(vault_query, "sessions", return_value=rows):
            with self.assertRaisesRegex(RuntimeError, "AMBIGUOUS_CHAT_NAME"):
                vault_query.resolve_session("同名")
            self.assertIs(vault_query.resolve_session(session_tag="b" * 16), rows[1])


class PackagingTests(unittest.TestCase):
    def test_setup_scripts_enforce_the_declared_platform_scope(self) -> None:
        root = Path(__file__).resolve().parents[1]
        mac_setup = (root / "setup.sh").read_text(encoding="utf-8")
        windows_setup = (root / "setup.ps1").read_text(encoding="utf-8")
        for required in ('sys.platform == "darwin"', '"arm64"', 'struct.calcsize("P") == 8'):
            self.assertIn(required, mac_setup)
        for required in (
            "sys.platform == 'win32'", "struct.calcsize('P') == 8", "'amd64'",
            "'x86_64'", "sys.getwindowsversion().build >= 22000",
        ):
            self.assertIn(required, windows_setup)
        self.assertTrue(windows_setup.rstrip().endswith("$global:LASTEXITCODE = 0"))

    def test_installed_skill_uses_repository_virtual_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            destination = install_skill(temp / "codex")
            root = temp / "repo"
            root.mkdir()
            (root / "wechat_manager.py").write_text(
                "import sys\nprint(sys.executable)\n", encoding="utf-8",
            )
            venv.EnvBuilder(with_pip=False).create(root / ".venv")
            expected = (
                root / ".venv/Scripts/python.exe" if os.name == "nt"
                else root / ".venv/bin/python"
            ).resolve()
            completed = subprocess.run(
                [sys.executable, str(destination / "scripts/run_manager.py"), "--version"],
                capture_output=True, text=True, check=True,
                env={**os.environ, "WECHAT_MANAGER_HOME": str(root)},
            )
            self.assertEqual(Path(completed.stdout.strip()).resolve(), expected)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_private_tree_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "vault"
            with patch.multiple(
                manager_config,
                PRIVATE_ROOT=root,
                KEYS_FILE=root / "secrets/keys",
                DECRYPTED_DIR=root / "decrypted/current",
                STATE_FILE=root / "state/state.json",
                MANIFEST_DIR=root / "manifests",
                AUDIT_DIR=root / "audit",
                EXPORTS_DIR=root / "exports",
            ):
                manager_config.ensure_private_tree()
                paths = (
                    manager_config.PRIVATE_ROOT,
                    manager_config.KEYS_FILE.parent,
                    manager_config.DECRYPTED_DIR.parent,
                    manager_config.DECRYPTED_DIR,
                    manager_config.STATE_FILE.parent,
                    manager_config.MANIFEST_DIR,
                    manager_config.AUDIT_DIR,
                    manager_config.EXPORTS_DIR,
                )
                self.assertTrue(all(path.stat().st_mode & 0o777 == 0o700 for path in paths))

    @unittest.skipUnless(sys.platform == "darwin", "macOS process boundary")
    def test_macos_pid_must_match_exact_copy_executable(self) -> None:
        expected = Path("/private/copy/WeChat")
        with (
            patch.object(capture_keys_macos, "validate_signed_copy", return_value=expected),
            patch.object(capture_keys_macos, "process_executable", return_value=Path("/private/other/WeChat")),
        ):
            with self.assertRaisesRegex(RuntimeError, "PID does not belong"):
                capture_keys_macos.validate_copy_process(123, Path("/private/copy.app"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS process boundary")
    def test_macos_capture_requires_exclusive_copy(self) -> None:
        with patch.object(capture_keys_macos, "running_wechat_pids", return_value={12, 13}):
            with self.assertRaisesRegex(RuntimeError, "every other WeChat"):
                capture_keys_macos.require_exclusive_copy(12)

    def test_macos_capture_process_detection_fails_closed(self) -> None:
        completed = subprocess.CompletedProcess(["pgrep"], 2, stdout="", stderr="failed")
        with patch.object(capture_keys_macos.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "WECHAT_PROCESS_CHECK_FAILED"):
                capture_keys_macos.running_wechat_pids()


class WindowsProcessAccessTests(unittest.TestCase):
    def test_module_inspection_access_denied_has_a_stable_code(self) -> None:
        completed = subprocess.CompletedProcess(
            ["powershell"], capture_keys_windows.ERROR_ACCESS_DENIED,
            stdout="", stderr="private localized error",
        )
        with patch.object(
            capture_keys_windows.subprocess, "run", return_value=completed,
        ) as run:
            with self.assertRaisesRegex(
                capture_keys_windows.ProcessInspectionAccessDenied,
                "PROCESS_MEMORY_ACCESS_DENIED",
            ):
                capture_keys_windows.process_info(123)
        powershell_script = run.call_args.args[0][-1]
        self.assertIn("$ErrorActionPreference = 'Stop'", powershell_script)

    def test_open_process_failure_captures_win32_error_immediately(self) -> None:
        class FakeKernel32:
            def __init__(self) -> None:
                self.last_error = 999

            def SetLastError(self, value: int) -> None:
                self.last_error = value

            def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
                self.last_error = capture_keys_windows.ERROR_ACCESS_DENIED
                return 0

            def GetLastError(self) -> int:
                return self.last_error

        handle, error = capture_keys_windows.open_process_for_scan(FakeKernel32(), 123)
        self.assertFalse(handle)
        self.assertEqual(error, capture_keys_windows.ERROR_ACCESS_DENIED)

    def test_only_all_access_denied_targets_get_stable_stop_code(self) -> None:
        denied = {"opened": 0, "bytes_read": 0, "markers": 0, "open_error": 5}
        other_error = {"opened": 0, "bytes_read": 0, "markers": 0, "open_error": 87}
        opened_without_candidate = {"opened": 1, "bytes_read": 10, "markers": 0, "open_error": 0}

        self.assertEqual(
            capture_keys_windows.process_memory_access_stop_reason([denied, denied]),
            "PROCESS_MEMORY_ACCESS_DENIED",
        )
        self.assertIsNone(capture_keys_windows.process_memory_access_stop_reason([]))
        self.assertIsNone(
            capture_keys_windows.process_memory_access_stop_reason([denied, other_error])
        )
        self.assertIsNone(
            capture_keys_windows.process_memory_access_stop_reason([denied, opened_without_candidate])
        )


class ImportSafetyTests(unittest.TestCase):
    def test_delete_source_requires_protected_store_readback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "db_storage"
            paths = core_paths(root, (0,))
            keys: dict[str, str] = {}
            for index, rel in enumerate(paths):
                key = bytes([index + 1]) * 32
                (root / rel).write_bytes(authenticated_page(key, bytes([index + 10]) * 16))
                keys[rel] = key.hex()
            source = Path(directory) / "keys.json"
            source.write_text(json.dumps({"keys": keys}), encoding="utf-8")
            config = {
                "db_base_path": str(root), "account_tag": "account",
                "core_databases": list(paths),
            }
            with (
                patch.object(import_keys, "load_config", return_value=config),
                patch.object(import_keys, "require_supported_platform"),
                patch.object(import_keys, "save_secret_json"),
                patch.object(import_keys, "load_secret_json", return_value={"account_tag": "wrong", "keys": {}}),
                patch.object(sys, "argv", ["import_keys.py", "--file", str(source), "--delete-source"]),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(import_keys.main(), 5)
            self.assertTrue(source.is_file())


if __name__ == "__main__":
    unittest.main()
