"""Find SocksTether networks and join them using netsh (no admin rights needed)."""
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from xml.sax.saxutils import escape

import diag

SSID_PREFIX = "DIRECT-ST-"
_WIN = sys.platform == "win32"


@dataclass(frozen=True)
class Network:
    ssid: str
    signal: int  # percent, 0 if unknown


def parse_networks(text):
    """Parse `netsh wlan show networks mode=bssid`. Only relies on the locale-independent
    'SSID <n> : name' lines and 'NN%' signal values, so it works on any Windows language."""
    found = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^\s*SSID\s+\d+\s*:\s?(.*)$", line)
        if m:
            current = m.group(1).strip()
            if current:
                found.setdefault(current, 0)
            continue
        if current:
            s = re.search(r":\s*(\d{1,3})\s*%", line)
            if s:
                found[current] = max(found[current], min(100, int(s.group(1))))
    return [Network(k, v) for k, v in found.items()]


def socks_networks(text):
    nets = [n for n in parse_networks(text) if n.ssid.startswith(SSID_PREFIX)]
    return sorted(nets, key=lambda n: (-n.signal, n.ssid))


def profile_xml(ssid, password):
    name, key = escape(ssid), escape(password)
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{name}</name>
  <SSIDConfig><SSID><name>{name}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>{key}</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>
"""


def _run(args, timeout=20):
    """Run a command (list, or a string when exact quoting matters). Never raises: returns (returncode, output).
    stdin must be DEVNULL: in a windowed (no-console) app an inherited stdin makes subprocess fail with
    'The handle is invalid'."""
    kw = {"stdin": subprocess.DEVNULL}
    if _WIN:
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
        kw["encoding"] = "oem"
    else:
        kw["encoding"] = "utf-8"
    shown = args if isinstance(args, str) else " ".join(args)
    try:
        p = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout, **kw)
        rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        rc, out = 1, f"{type(e).__name__}: {e}"
    diag.log(f"$ {shown}\n  -> rc={rc} {out.strip()[:600]}")
    return rc, out


def _request_scan():
    """Ask the Wi-Fi driver for a fresh scan (best effort; netsh alone often returns cached results)."""
    if not _WIN:
        return
    try:
        import ctypes
        from ctypes import wintypes
        wlan = ctypes.windll.wlanapi
        handle = wintypes.HANDLE()
        negotiated = wintypes.DWORD()
        if wlan.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle)) != 0:
            return
        try:
            plist = ctypes.c_void_p()
            if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(plist)) == 0:
                count = ctypes.cast(plist, ctypes.POINTER(wintypes.DWORD))[0]
                # WLAN_INTERFACE_INFO_LIST: DWORD count, DWORD index, then 532-byte entries starting with the GUID
                base = plist.value + 8
                for i in range(count):
                    wlan.WlanScan(handle, ctypes.c_void_p(base + i * 532), None, None, None)
                wlan.WlanFreeMemory(plist)
        finally:
            wlan.WlanCloseHandle(handle, None)
    except Exception:
        pass


def scan():
    _request_scan()
    _, out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    return socks_networks(out)


def connect(ssid, password):
    """Create a profile for the network and ask Windows to join it."""
    if '"' in ssid:
        raise RuntimeError("This network name contains a quote character, which isn't supported.")
    diag.add_secret(password)
    fd, path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(profile_xml(ssid, password))
        # exact quoting matters to netsh: the quotes go around the value only, not around filename=...
        rc, out = _run(f'netsh wlan add profile filename="{path}" user=current')
        if rc != 0:
            raise RuntimeError(f"Windows refused the Wi-Fi profile: {out.strip()}")
    finally:
        try:
            os.remove(path)  # it contains the password in plain text
        except OSError:
            pass
    rc, out = _run(f'netsh wlan connect name="{ssid}" ssid="{ssid}"')
    if rc != 0:
        raise RuntimeError(f"Windows couldn't start the connection: {out.strip()}")


def disconnect(ssid):
    _run(["netsh", "wlan", "disconnect"])
    if '"' not in ssid:
        _run(f'netsh wlan delete profile name="{ssid}"')


def ip_config_for(ssid):
    """(adapter alias, IPv4 default gateway) of the adapter joined to this network, or (None, None).
    Locale-independent: asks PowerShell for objects, not localized text."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", ssid):
        return None, None
    ps = ("$c = Get-NetIPConfiguration | Where-Object { $_.NetProfile.Name -like '" + ssid + "*' "
          "-and $_.IPv4DefaultGateway } | Select-Object -First 1; "
          "if ($c) { $c.InterfaceAlias; $c.IPv4DefaultGateway.NextHop }")
    _, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=25)
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if len(lines) < 2:
        return None, None
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", lines[-1])
    return (lines[0], m.group(1)) if m else (None, None)


def gateway_for(ssid):
    return ip_config_for(ssid)[1]


def interface_alias_for(ssid):
    return ip_config_for(ssid)[0]


def wait_for_gateway(ssid, timeout=30, should_stop=lambda: False):
    end = time.time() + timeout
    while time.time() < end and not should_stop():
        gw = gateway_for(ssid)
        if gw:
            return gw
        time.sleep(1.0)
    return None
