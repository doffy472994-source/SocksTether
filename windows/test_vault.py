import json
import os
import tempfile
import unittest

import diag
import vault


def scramble(b):  # stand-in for DPAPI in tests: reversible, and visibly not plaintext
    return bytes(x ^ 0x5A for x in b)


class VaultTests(unittest.TestCase):
    def make(self):
        d = tempfile.mkdtemp()
        return vault.Vault(os.path.join(d, "v", "vault.json"), scramble, scramble), d

    def test_roundtrip_and_not_plaintext_on_disk(self):
        v, _ = self.make()
        v.set("DIRECT-ST-Ricky", "hunter2hunter2")
        self.assertTrue(v.has("DIRECT-ST-Ricky"))
        self.assertEqual(v.get("DIRECT-ST-Ricky"), "hunter2hunter2")
        with open(v.path) as f:
            raw = f.read()
        self.assertNotIn("hunter2", raw)
        self.assertIn("DIRECT-ST-Ricky", json.loads(raw))

    def test_forget_and_overwrite(self):
        v, _ = self.make()
        v.set("a", "one"); v.set("b", "two"); v.set("a", "three")
        self.assertEqual(v.get("a"), "three")
        v.forget("a")
        self.assertIsNone(v.get("a")); self.assertFalse(v.has("a"))
        self.assertEqual(v.get("b"), "two")
        v.forget("nope")  # no error

    def test_corrupt_or_foreign_entries_read_as_missing(self):
        v, _ = self.make()
        os.makedirs(os.path.dirname(v.path))
        with open(v.path, "w") as f:
            f.write("{not json")
        self.assertIsNone(v.get("x"))
        v.set("x", "ok")  # recovers by rewriting
        self.assertEqual(v.get("x"), "ok")

        def boom(b):
            raise OSError("different user")
        v2 = vault.Vault(v.path, scramble, boom)
        self.assertIsNone(v2.get("x"))  # entry can't be decrypted -> prompt again, no crash


class DiagTests(unittest.TestCase):
    def test_redacts_secret_and_url_encoded_form(self):
        os.environ["APPDATA"] = tempfile.mkdtemp()
        diag.add_secret("p@ss w0rd!")
        diag.log("cmd with p@ss w0rd! and socks5://u:p%40ss%20w0rd%21@h")
        text = open(diag.path()).read()
        self.assertNotIn("p@ss w0rd!", text)
        self.assertNotIn("p%40ss%20w0rd%21", text)
        self.assertIn("***", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
