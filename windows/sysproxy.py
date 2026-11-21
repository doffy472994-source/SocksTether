"""Windows system proxy (HKCU Internet Settings) with a crash-safe backup of the previous settings."""
import json
import os

KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect")
DWORD, SZ = 4, 1  # winreg.REG_DWORD, winreg.REG_SZ


class WinRegistry:
    def __init__(self):
        import winreg
        self.w = winreg

    def _open(self, access):
        return self.w.OpenKey(self.w.HKEY_CURRENT_USER, KEY, 0, access)

    def get(self, name):
        try:
            with self._open(self.w.KEY_READ) as k:
                v, t = self.w.QueryValueEx(k, name)
                return [v, t]
        except FileNotFoundError:
            return None

    def set(self, name, value, typ):
        with self._open(self.w.KEY_SET_VALUE) as k:
            self.w.SetValueEx(k, name, 0, typ, value)

    def delete(self, name):
        try:
            with self._open(self.w.KEY_SET_VALUE) as k:
                self.w.DeleteValue(k, name)
        except FileNotFoundError:
            pass

    def notify(self):
        import ctypes
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


def default_backup_path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "SocksTether", "proxy_backup.json")


class SystemProxy:
    def __init__(self, reg=None, backup_path=None):
        self.reg = reg or WinRegistry()
        self.backup_path = backup_path or default_backup_path()

    def enable(self, port):
        # Never overwrite an existing backup: it holds the user's real settings if we crashed earlier.
        if not os.path.exists(self.backup_path):
            os.makedirs(os.path.dirname(self.backup_path), exist_ok=True)
            with open(self.backup_path, "w") as f:
                json.dump({n: self.reg.get(n) for n in NAMES}, f)
        self.reg.set("ProxyServer", f"127.0.0.1:{port}", SZ)
        self.reg.set("ProxyOverride", "localhost;127.*;10.*;192.168.*;<local>", SZ)
        self.reg.set("ProxyEnable", 1, DWORD)
        self.reg.delete("AutoConfigURL")  # a PAC script would override our manual proxy
        self.reg.set("AutoDetect", 0, DWORD)
        self.reg.notify()

    def restore(self):
        """Put the user's original settings back. Safe to call when nothing was changed."""
        if not os.path.exists(self.backup_path):
            return False
        try:
            with open(self.backup_path) as f:
                saved = json.load(f)
        except (OSError, ValueError):
            saved = {"ProxyEnable": [0, DWORD]}
        for name in NAMES:
            entry = saved.get(name)
            if entry is None:
                self.reg.delete(name)
            else:
                self.reg.set(name, entry[0], entry[1])
        self.reg.notify()
        os.remove(self.backup_path)
        return True

    def has_pending_backup(self):
        return os.path.exists(self.backup_path)
