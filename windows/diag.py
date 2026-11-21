"""Tiny persistent log (%APPDATA%\\SocksTether\\log.txt) so failures can be diagnosed after the fact."""
import os
import threading
import time
import traceback
from urllib.parse import quote

_lock = threading.Lock()
_secrets = set()


def path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "SocksTether", "log.txt")


def add_secret(s):
    if s:
        _secrets.add(s)
        _secrets.add(quote(s, safe=""))


def redact(text):
    for s in sorted(_secrets, key=len, reverse=True):
        text = text.replace(s, "***")
    return text


def start():
    """Keep the file small: drop old content when it grows past ~300 KB."""
    p = path()
    try:
        if os.path.getsize(p) > 300_000:
            os.remove(p)
    except OSError:
        pass
    log("---- SocksTether started ----")


def log(msg):
    line = f"{time.strftime('%H:%M:%S')}  {redact(str(msg))}\n"
    try:
        with _lock:
            os.makedirs(os.path.dirname(path()), exist_ok=True)
            with open(path(), "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass


def exc(prefix):
    log(prefix + "\n" + traceback.format_exc())
