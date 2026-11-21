"""Remembers Wi-Fi passwords per network, encrypted with the current Windows user's key (DPAPI),
so they are unreadable to other users and other PCs. Nothing is stored in plain text."""
import base64
import json
import os
import sys


def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    inb = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # CryptProtectData / CryptUnprotectData(in, descr, entropy, reserved, prompt, flags, out)
    ok = fn(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("Windows data protection failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def default_path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "SocksTether", "vault.json")


class Vault:
    def __init__(self, path=None, protect=None, unprotect=None):
        self.path = path or default_path()
        if protect is None:
            if sys.platform == "win32":
                protect, unprotect = (lambda b: _dpapi(b, True)), (lambda b: _dpapi(b, False))
            else:  # dev/test only; the shipped app is Windows
                protect, unprotect = (lambda b: b), (lambda b: b)
        self._p, self._u = protect, unprotect

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, self.path)

    def has(self, ssid):
        return ssid in self._load()

    def get(self, ssid):
        blob = self._load().get(ssid)
        if not blob:
            return None
        try:
            return self._u(base64.b64decode(blob)).decode("utf-8")
        except Exception:
            return None  # different user/PC or corrupted: treat as not saved

    def set(self, ssid, password):
        d = self._load()
        d[ssid] = base64.b64encode(self._p(password.encode("utf-8"))).decode("ascii")
        self._save(d)

    def forget(self, ssid):
        d = self._load()
        if d.pop(ssid, None) is not None:
            self._save(d)
