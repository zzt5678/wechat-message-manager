from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from Crypto.Cipher import AES

from capture_keys_macos import HOOK, match_candidate, plan as macos_plan
from capture_keys_windows import derive_enc_key, plan as windows_plan, recover
from dpapi_store import load_secret_json, save_secret_json
from import_keys import verify_key
from manager_config import CORE_DATABASES
from refresh_vault import decrypt_to_temp, hmac_key


def authenticated_page(key: bytes, salt: bytes) -> bytes:
    page = bytearray(4096)
    page[:16] = salt
    page[16:-64] = bytes((index * 17 + 11) % 256 for index in range(16, 4096 - 64))
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)
    digest = hmac.new(mac_key, page[16:-64], hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    page[-64:] = digest.digest()
    return bytes(page)


class SecurityBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
    def test_dpapi_round_trip_does_not_store_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.dpapi"
            secret = {"keys": {"message/message_0.db": "ab" * 32}}
            save_secret_json(secret, path)
            self.assertEqual(load_secret_json(path), secret)
            self.assertNotIn(("ab" * 32).encode("ascii"), path.read_bytes())

    def test_windows_capture_plan_is_non_executing_and_redacted(self) -> None:
        value = windows_plan({"wechat_version": "test"})
        encoded = json.dumps(value)
        self.assertEqual(value["status"], "READY_FOR_KEY_CAPTURE_APPROVAL")
        self.assertFalse(value["injects_or_hooks"])
        self.assertFalse(value["writes_process_memory"])
        self.assertNotIn(str(Path.home()), encoded)

    def test_macos_plan_discloses_hook(self) -> None:
        value = macos_plan()
        self.assertTrue(value["hook_installed_in_copy_process"])
        self.assertFalse(value["modifies_original_wechat"])
        self.assertFalse(value["ui_automation"])
        self.assertIn("Interceptor.attach", HOOK)

    def test_macos_candidate_is_accepted_only_after_hmac(self) -> None:
        key = bytes(range(32))
        targets = {"contact/contact.db": authenticated_page(key, bytes(range(16)))}
        found: dict[str, str] = {}
        self.assertEqual(match_candidate(bytes(reversed(key)), targets, found), 0)
        self.assertEqual(match_candidate(key, targets, found), 1)
        self.assertEqual(set(found), {"contact/contact.db"})

    def test_hmac_rejects_wrong_key(self) -> None:
        key = bytes(range(32))
        page = authenticated_page(key, bytes(range(16)))
        self.assertTrue(verify_key(key, page))
        self.assertFalse(verify_key(bytes(reversed(key)), page))

    def test_v4_recovery_requires_every_core_database(self) -> None:
        passphrase = bytes(range(32))
        mask = bytes([0xA5] * 32)
        raw = bytes(a ^ b for a, b in zip(passphrase, mask))
        pages = {}
        for index, rel in enumerate(CORE_DATABASES):
            salt = bytes([index + 1]) * 16
            key = derive_enc_key(passphrase, salt + bytes(4080))
            pages[rel] = authenticated_page(key, salt)
        result = recover([raw], [mask], pages)
        self.assertIsNotNone(result)
        _, keys = result
        self.assertEqual(set(keys), set(CORE_DATABASES))

    def test_page_decryption_round_trip(self) -> None:
        key = bytes(range(32))
        salt = bytes(range(16, 32))
        iv = bytes(range(32, 48))
        plaintext = bytearray(4096)
        plaintext[:16] = b"SQLite format 3\x00"
        plaintext[16:4016] = bytes((index * 13 + 7) % 256 for index in range(4000))
        encrypted = bytearray(4096)
        encrypted[:16] = salt
        encrypted[16:4016] = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes(plaintext[16:4016]))
        encrypted[4016:4032] = iv
        digest = hmac.new(hmac_key(key, salt), encrypted[16:4032], hashlib.sha512)
        digest.update(struct.pack("<I", 1))
        encrypted[-64:] = digest.digest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source.db", root / "plain.db"
            source.write_bytes(encrypted)
            temporary = decrypt_to_temp(source, destination, key.hex())
            output = temporary.read_bytes()
        self.assertEqual(output[:16], b"SQLite format 3\x00")
        self.assertEqual(output[18:4016], plaintext[18:4016])


if __name__ == "__main__":
    unittest.main()
