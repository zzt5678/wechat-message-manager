from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

import refresh_vault
import vault_query


def create_marker_database(path: Path, marker: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        db.execute("INSERT INTO marker VALUES (?)", (marker,))
        db.commit()


def read_marker(path: Path) -> str:
    with closing(sqlite3.connect(path)) as db:
        return str(db.execute("SELECT value FROM marker").fetchone()[0])


class SyntheticRefreshVault:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.decrypted = root / "vault/decrypted/current"
        self.state_file = root / "vault/state/decrypt-state.json"
        self.manifest_dir = root / "vault/manifests"
        self.audit_dir = root / "vault/audit"
        self.candidates = root / "candidates"
        self.core = (
            "contact/contact.db",
            "session/session.db",
            "message/message_0.db",
            "message/message_7.db",
            "message/message_resource.db",
        )
        self.keys = {
            rel: bytes([index + 1]) * 32
            for index, rel in enumerate(self.core)
        }
        self.config = {
            "schema_version": 2,
            "db_base_path": str(self.source),
            "core_databases": list(self.core),
        }
        for directory in (
            self.decrypted, self.state_file.parent, self.manifest_dir,
            self.audit_dir, self.candidates,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        for index, rel in enumerate(self.core):
            source_path = self.source / rel
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes((f"encrypted-source-{index}-v1".encode("ascii") * 256)[:4096])
            create_marker_database(self.decrypted / rel, f"verified-{index}")
            create_marker_database(self.candidates / rel, f"candidate-{index}")
        self.write_current_state()

    def fingerprints(self) -> dict[str, object]:
        return {
            rel: refresh_vault.fingerprint(self.source / rel, self.keys[rel].hex())
            for rel in self.core
        }

    def write_current_state(self) -> None:
        self.state_file.write_text(
            json.dumps(self.fingerprints(), indent=2) + "\n", encoding="utf-8",
        )

    def plaintext_snapshot(self) -> dict[str, bytes]:
        return {rel: (self.decrypted / rel).read_bytes() for rel in self.core}

    def fake_decrypt(self, source: Path, destination: Path, _key_hex: str) -> Path:
        rel = source.relative_to(self.source).as_posix()
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="synthetic-", dir=str(destination.parent))
        os.close(fd)
        temp_path = Path(temp_name)
        shutil.copyfile(self.candidates / rel, temp_path)
        return temp_path

    @contextmanager
    def patched(self, decrypt=None):
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(
                refresh_vault,
                DECRYPTED_DIR=self.decrypted,
                STATE_FILE=self.state_file,
                MANIFEST_DIR=self.manifest_dir,
                AUDIT_DIR=self.audit_dir,
            ))
            stack.enter_context(patch.object(refresh_vault, "ensure_private_tree"))
            stack.enter_context(patch.object(refresh_vault, "require_supported_platform"))
            stack.enter_context(patch.object(refresh_vault, "require_wechat_stopped"))
            stack.enter_context(patch.object(refresh_vault, "load_config", return_value=self.config))
            stack.enter_context(patch.object(
                refresh_vault, "load_secret_json",
                return_value={"keys": {rel: key.hex() for rel, key in self.keys.items()}},
            ))
            stack.enter_context(patch.object(
                refresh_vault, "decrypt_to_temp", decrypt or self.fake_decrypt,
            ))
            yield

    def run(self, *arguments: str, decrypt=None) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            self.patched(decrypt),
            patch.object(sys, "argv", ["refresh_vault.py", *arguments]),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = refresh_vault.main()
        return result, stdout.getvalue(), stderr.getvalue()


class RefreshIntegrationTests(unittest.TestCase):
    def test_full_refresh_commits_every_database_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRefreshVault(Path(directory))
            result, output, error = fixture.run("--mode", "full")
            self.assertEqual(result, 0, error)
            payload = json.loads(output)
            self.assertEqual(payload["status"], "VERIFIED_REFRESH")
            self.assertEqual({row["status"] for row in payload["records"]}, {"ok"})
            for index, rel in enumerate(fixture.core):
                self.assertEqual(read_marker(fixture.decrypted / rel), f"candidate-{index}")
            self.assertEqual(
                json.loads(fixture.state_file.read_text(encoding="utf-8")),
                fixture.fingerprints(),
            )
            self.assertFalse(list(fixture.decrypted.parent.glob(".refresh-*")))

    def test_incremental_refresh_only_commits_changed_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRefreshVault(Path(directory))
            changed = fixture.core[3]
            (fixture.source / changed).write_bytes(b"encrypted-source-changed" * 256)
            decrypted: list[str] = []

            def recording_decrypt(source: Path, destination: Path, key_hex: str) -> Path:
                decrypted.append(source.relative_to(fixture.source).as_posix())
                return fixture.fake_decrypt(source, destination, key_hex)

            result, output, error = fixture.run("--mode", "incremental", decrypt=recording_decrypt)
            self.assertEqual(result, 0, error)
            self.assertEqual(decrypted, [changed])
            records = {row["rel"]: row["status"] for row in json.loads(output)["records"]}
            self.assertEqual(records[changed], "ok")
            self.assertTrue(all(
                status == "unchanged" for rel, status in records.items() if rel != changed
            ))
            for index, rel in enumerate(fixture.core):
                expected = f"candidate-{index}" if rel == changed else f"verified-{index}"
                self.assertEqual(read_marker(fixture.decrypted / rel), expected)
            self.assertEqual(
                json.loads(fixture.state_file.read_text(encoding="utf-8")),
                fixture.fingerprints(),
            )

    def test_dry_run_success_never_decrypts_or_changes_verified_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRefreshVault(Path(directory))
            state_before = fixture.state_file.read_bytes()
            plaintext_before = fixture.plaintext_snapshot()

            def forbidden_decrypt(*_args, **_kwargs):
                raise AssertionError("dry-run must not decrypt")

            result, output, error = fixture.run(
                "--mode", "full", "--dry-run", decrypt=forbidden_decrypt,
            )
            self.assertEqual(result, 0, error)
            payload = json.loads(output)
            self.assertEqual(payload["status"], "DRY_RUN_OK")
            self.assertEqual({row["status"] for row in payload["records"]}, {"would_refresh"})
            self.assertEqual(fixture.state_file.read_bytes(), state_before)
            self.assertEqual(fixture.plaintext_snapshot(), plaintext_before)
            self.assertFalse(list(fixture.manifest_dir.iterdir()))

    def test_staging_failure_preserves_full_and_incremental_verified_assets(self) -> None:
        for mode in ("full", "incremental"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticRefreshVault(Path(directory))
                if mode == "incremental":
                    for rel in fixture.core[:2]:
                        (fixture.source / rel).write_bytes((rel + "-changed").encode() * 256)
                state_before = fixture.state_file.read_bytes()
                plaintext_before = fixture.plaintext_snapshot()
                calls = 0

                def failing_decrypt(source: Path, destination: Path, key_hex: str) -> Path:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise RuntimeError("synthetic decrypt failure")
                    return fixture.fake_decrypt(source, destination, key_hex)

                result, _output, error = fixture.run("--mode", mode, decrypt=failing_decrypt)
                self.assertEqual(result, 2)
                self.assertIn("synthetic decrypt failure", error)
                self.assertEqual(fixture.state_file.read_bytes(), state_before)
                self.assertEqual(fixture.plaintext_snapshot(), plaintext_before)
                self.assertFalse(list(fixture.decrypted.parent.glob(".refresh-*")))

    def test_final_source_freshness_failure_preserves_verified_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRefreshVault(Path(directory))
            state_before = fixture.state_file.read_bytes()
            plaintext_before = fixture.plaintext_snapshot()

            def mutate_earlier_source(source: Path, destination: Path, key_hex: str) -> Path:
                temp_path = fixture.fake_decrypt(source, destination, key_hex)
                if source.relative_to(fixture.source).as_posix() == fixture.core[-1]:
                    (fixture.source / fixture.core[0]).write_bytes(b"changed-after-staging" * 256)
                return temp_path

            result, _output, error = fixture.run(
                "--mode", "full", decrypt=mutate_earlier_source,
            )
            self.assertEqual(result, 2)
            self.assertIn("STALE_VAULT", error)
            self.assertEqual(fixture.state_file.read_bytes(), state_before)
            self.assertEqual(fixture.plaintext_snapshot(), plaintext_before)

    def test_commit_and_state_failures_restore_entire_plaintext_batch(self) -> None:
        for failure in ("second_replace", "state_write"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticRefreshVault(Path(directory))
                state_before = fixture.state_file.read_bytes()
                plaintext_before = fixture.plaintext_snapshot()
                real_replace = os.replace
                real_atomic_write = refresh_vault.atomic_write_json
                replacements = 0

                def flaky_replace(source, destination):
                    nonlocal replacements
                    destination_path = Path(destination)
                    if destination_path in {fixture.decrypted / rel for rel in fixture.core}:
                        replacements += 1
                        if failure == "second_replace" and replacements == 2:
                            raise OSError("synthetic commit failure")
                    return real_replace(source, destination)

                def flaky_atomic_write(path: Path, value) -> None:
                    if failure == "state_write" and Path(path) == fixture.state_file:
                        raise OSError("synthetic state failure")
                    real_atomic_write(path, value)

                with (
                    patch.object(refresh_vault.os, "replace", side_effect=flaky_replace),
                    patch.object(refresh_vault, "atomic_write_json", side_effect=flaky_atomic_write),
                ):
                    result, _output, error = fixture.run("--mode", "full")
                self.assertEqual(result, 2)
                self.assertIn("prior verified plaintext was restored", error)
                self.assertEqual(fixture.state_file.read_bytes(), state_before)
                self.assertEqual(fixture.plaintext_snapshot(), plaintext_before)
                self.assertFalse(list(fixture.decrypted.parent.glob(".refresh-*")))

    def test_failed_dry_run_preserves_verified_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRefreshVault(Path(directory))
            state_before = fixture.state_file.read_bytes()
            plaintext_before = fixture.plaintext_snapshot()
            source = fixture.source / fixture.core[1]
            source.with_name(source.name + "-wal").write_bytes(b"pending")
            result, _output, error = fixture.run("--mode", "full", "--dry-run")
            self.assertEqual(result, 2)
            self.assertIn("SOURCE_TRANSACTION_LOG_PRESENT_UNSUPPORTED", error)
            self.assertEqual(fixture.state_file.read_bytes(), state_before)
            self.assertEqual(fixture.plaintext_snapshot(), plaintext_before)

    def test_abrupt_partial_commit_leaves_freshness_hard_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRefreshVault(Path(directory))
            state_before = fixture.state_file.read_bytes()
            (fixture.source / fixture.core[0]).write_bytes(b"changed-before-crash" * 256)
            next_state = fixture.fingerprints()
            staging = fixture.decrypted.parent / ".synthetic-crash"
            staged: dict[str, Path] = {}
            for rel in fixture.core:
                path = staging / "candidate" / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(fixture.candidates / rel, path)
                staged[rel] = path
            real_replace = os.replace
            replacements = 0

            def crash_on_second_install(source, destination):
                nonlocal replacements
                destination_path = Path(destination)
                if destination_path in {fixture.decrypted / rel for rel in fixture.core}:
                    replacements += 1
                    if replacements == 2:
                        raise KeyboardInterrupt("synthetic abrupt termination")
                return real_replace(source, destination)

            with (
                patch.multiple(
                    refresh_vault,
                    DECRYPTED_DIR=fixture.decrypted,
                    STATE_FILE=fixture.state_file,
                ),
                patch.object(refresh_vault.os, "replace", side_effect=crash_on_second_install),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    refresh_vault.commit_staged_databases(staged, next_state, staging)
            self.assertEqual(fixture.state_file.read_bytes(), state_before)
            with (
                patch.multiple(
                    vault_query,
                    DECRYPTED_DIR=fixture.decrypted,
                    STATE_FILE=fixture.state_file,
                ),
                patch.object(vault_query, "load_config", return_value=fixture.config),
                patch.object(vault_query, "load_secret_json", return_value={
                    "keys": {rel: key.hex() for rel, key in fixture.keys.items()},
                }),
                patch.object(vault_query, "require_wechat_stopped"),
            ):
                with self.assertRaisesRegex(RuntimeError, "STALE_VAULT"):
                    vault_query.freshness_gate()


class SyntheticQueryVault:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.decrypted = root / "decrypted"
        self.state_file = root / "state.json"
        self.core = (
            "contact/contact.db",
            "session/session.db",
            "message/message_0.db",
            "message/message_9.db",
            "message/message_resource.db",
        )
        self.keys = {rel: (bytes([index + 20]) * 32).hex() for index, rel in enumerate(self.core)}
        self.config = {
            "schema_version": 2,
            "db_base_path": str(self.source),
            "core_databases": list(self.core),
        }
        self.users = ("internal_private_alpha_123", "internal_private_beta_456")
        self.sender_username = "internal_private_sender_789"
        self.day = datetime(2026, 7, 15).astimezone()
        self.message_times = (
            int((self.day + timedelta(hours=9)).timestamp()),
            int((self.day + timedelta(hours=10)).timestamp()),
        )
        self._create_sources()
        self._create_plaintext()
        self.state_file.write_text(json.dumps({
            rel: refresh_vault.fingerprint(self.source / rel, self.keys[rel])
            for rel in self.core
        }), encoding="utf-8")

    def _create_sources(self) -> None:
        for index, rel in enumerate(self.core):
            path = self.source / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((f"source-{index}".encode("ascii") * 512)[:4096])

    def _create_plaintext(self) -> None:
        contact = self.decrypted / "contact/contact.db"
        contact.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(contact)) as db:
            db.execute("CREATE TABLE contact (username TEXT, remark TEXT, nick_name TEXT)")
            db.executemany("INSERT INTO contact VALUES (?, ?, ?)", (
                (self.users[0], "Alpha chat", ""),
                (self.users[1], "Beta chat", ""),
                (self.sender_username, "Visible sender", ""),
            ))
            db.commit()

        session = self.decrypted / "session/session.db"
        session.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(session)) as db:
            db.execute("CREATE TABLE SessionNoContactInfoTable (username TEXT, session_title TEXT)")
            db.execute(
                "CREATE TABLE SessionTable (username TEXT, type INTEGER, unread_count INTEGER, "
                "summary TEXT, last_timestamp INTEGER, is_hidden INTEGER, sort_timestamp INTEGER)"
            )
            db.executemany("INSERT INTO SessionTable VALUES (?, ?, ?, ?, ?, ?, ?)", (
                (self.users[0], 1, 1, "alpha preview", self.message_times[0], 0, self.message_times[0]),
                (self.users[1], 1, 0, "beta preview", self.message_times[1], 0, self.message_times[1]),
            ))
            db.commit()

        self._create_message_shard(
            self.decrypted / "message/message_0.db", self.users[0],
            self.message_times[0], "alpha secret message",
        )
        self._create_message_shard(
            self.decrypted / "message/message_9.db", self.users[1],
            self.message_times[1], "beta secret message" * 20,
        )
        resource = self.decrypted / "message/message_resource.db"
        resource.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(resource)) as db:
            db.execute("CREATE TABLE resource_marker (value INTEGER)")
            db.commit()

    def _create_message_shard(self, path: Path, username: str, timestamp: int, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        table = "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE Name2Id (user_name TEXT)")
            db.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (1, ?)", (self.sender_username,))
            db.execute(
                f'CREATE TABLE "{table}" (local_id INTEGER, local_type INTEGER, '
                "real_sender_id INTEGER, create_time INTEGER, message_content TEXT)"
            )
            db.execute(
                f'INSERT INTO "{table}" VALUES (1, 1, 1, ?, ?)', (timestamp, text),
            )
            db.commit()

    @contextmanager
    def patched(self):
        with ExitStack() as stack:
            stack.enter_context(patch.multiple(
                vault_query, DECRYPTED_DIR=self.decrypted, STATE_FILE=self.state_file,
            ))
            stack.enter_context(patch.object(vault_query, "load_config", return_value=self.config))
            stack.enter_context(patch.object(
                vault_query, "load_secret_json", return_value={"keys": self.keys},
            ))
            stack.enter_context(patch.object(vault_query, "require_wechat_stopped"))
            stack.enter_context(patch.object(vault_query, "require_supported_platform"))
            yield

    def run(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            self.patched(),
            patch.object(sys, "argv", ["vault_query.py", *arguments]),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = vault_query.main()
        return result, stdout.getvalue(), stderr.getvalue()


class QueryIntegrationTests(unittest.TestCase):
    APPROVAL = "--i-understand-message-content-output"

    def test_status_requires_every_quick_check_to_return_ok(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticQueryVault(Path(directory))

            @contextmanager
            def failed_quick_check(_path: Path):
                class FailedDatabase:
                    @staticmethod
                    def execute(_statement: str):
                        class Result:
                            @staticmethod
                            def fetchone():
                                return ("database disk image is malformed",)

                        return Result()

                yield FailedDatabase()

            with patch.object(vault_query, "connect", side_effect=failed_quick_check):
                result, output, error = fixture.run("status")
            self.assertEqual(result, 2)
            self.assertEqual(output, "")
            self.assertIn("VAULT_INTEGRITY_CHECK_FAILED", error)
            self.assertNotIn("VERIFIED_FRESH_VAULT", error)

    def test_sessions_and_history_use_opaque_tags_across_dynamic_shards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticQueryVault(Path(directory))
            result, output, error = fixture.run("sessions", self.APPROVAL, "--limit", "20")
            self.assertEqual(result, 0, error)
            sessions = json.loads(output)
            encoded_sessions = json.dumps(sessions, ensure_ascii=False)
            for private in (*fixture.users, fixture.sender_username):
                self.assertNotIn(private, encoded_sessions)
            self.assertEqual({row["name"] for row in sessions}, {"Alpha chat", "Beta chat"})
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{16}", row["session_tag"]) for row in sessions))
            self.assertTrue(all("_username" not in row for row in sessions))

            expected = {
                "Alpha chat": "alpha secret message",
                "Beta chat": "beta secret message",
            }
            for session in sessions:
                result, output, error = fixture.run(
                    "history", "--session-tag", session["session_tag"], self.APPROVAL,
                    "--since", fixture.day.isoformat(),
                    "--until", (fixture.day + timedelta(days=1)).isoformat(),
                )
                self.assertEqual(result, 0, error)
                history = json.loads(output)
                self.assertEqual(len(history), 1)
                self.assertIn(expected[session["name"]], history[0]["text"])
                encoded_history = json.dumps(history, ensure_ascii=False)
                for private in (*fixture.users, fixture.sender_username):
                    self.assertNotIn(private, encoded_history)

    def test_digest_reads_noncontiguous_shards_and_honors_content_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticQueryVault(Path(directory))
            result, output, error = fixture.run(
                "digest-source", "--date", fixture.day.date().isoformat(),
                "--max-messages", "10", "--max-chars", "1000", self.APPROVAL,
            )
            self.assertEqual(result, 0, error)
            digest = json.loads(output)
            self.assertEqual(digest["message_count"], 2)
            self.assertEqual({chat["chat"] for chat in digest["chats"]}, {"Alpha chat", "Beta chat"})
            encoded = json.dumps(digest, ensure_ascii=False)
            self.assertIn("alpha secret message", encoded)
            self.assertIn("beta secret message", encoded)
            for private in (*fixture.users, fixture.sender_username):
                self.assertNotIn(private, encoded)

            budget = 40
            result, output, error = fixture.run(
                "digest-source", "--date", fixture.day.date().isoformat(),
                "--max-messages", "10", "--max-chars", str(budget), self.APPROVAL,
            )
            self.assertEqual(result, 0, error)
            bounded = json.loads(output)
            consumed = sum(
                len(chat["chat"]) + sum(len(message["sender"]) + len(message["text"]) for message in chat["messages"])
                for chat in bounded["chats"]
            )
            self.assertLessEqual(consumed, budget)
            self.assertTrue(bounded["truncated"])

    def test_history_honors_content_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticQueryVault(Path(directory))
            result, output, error = fixture.run("sessions", self.APPROVAL)
            self.assertEqual(result, 0, error)
            beta = next(row for row in json.loads(output) if row["name"] == "Beta chat")
            budget = 24
            result, output, error = fixture.run(
                "history", "--session-tag", beta["session_tag"], self.APPROVAL,
                "--since", fixture.day.isoformat(),
                "--until", (fixture.day + timedelta(days=1)).isoformat(),
                "--max-chars", str(budget),
            )
            self.assertEqual(result, 0, error)
            history = json.loads(output)
            consumed = sum(len(row["sender"]) + len(row["text"]) for row in history)
            self.assertLessEqual(consumed, budget)
            self.assertTrue(history)

    def test_real_second_freshness_gate_suppresses_built_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticQueryVault(Path(directory))
            original_history = vault_query.history
            changed = False

            def mutate_after_history(*args, **kwargs):
                nonlocal changed
                rows = original_history(*args, **kwargs)
                if not changed:
                    changed = True
                    (fixture.source / fixture.core[0]).write_bytes(b"source-changed-during-query" * 256)
                return rows

            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                fixture.patched(),
                patch.object(vault_query, "history", side_effect=mutate_after_history),
                patch.object(sys, "argv", [
                    "vault_query.py", "digest-source", "--date", fixture.day.date().isoformat(),
                    self.APPROVAL,
                ]),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = vault_query.main()
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("STALE_VAULT", stderr.getvalue())
            self.assertNotIn("secret message", stderr.getvalue())
            for private in (*fixture.users, fixture.sender_username):
                self.assertNotIn(private, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
