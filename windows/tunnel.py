"""System-wide tunnel: a virtual network adapter (Wintun) that sends ALL apps' traffic, TCP and UDP,
through the phone's SOCKS5 proxy using tun2socks. This is what makes games like Roblox work.
Needs administrator rights (creating an adapter and routes)."""
import os
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

import diag
import wifi

TUN_NAME = "SocksTether"
TUN_IP, TUN_MASK = "198.18.0.1", "255.255.255.0"  # 198.18/15 is reserved for benchmarking: won't clash with a LAN
DNS = ("1.1.1.1", "8.8.8.8")
_WIN = sys.platform == "win32"


class TunnelError(Exception):
    pass


def resource_dir():
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")


def is_admin():
    if _WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def tun2socks_args(exe, gateway, port, user, password, iface):
    proxy = f"socks5://{quote(user, safe='')}:{quote(password, safe='')}@{gateway}:{port}"
    # -interface pins tun2socks' own connections to the Wi-Fi adapter so they never loop back into the tunnel
    return [exe, "-device", f"tun://{TUN_NAME}", "-proxy", proxy, "-interface", iface, "-loglevel", "warn"]


def _kill_on_close_job():
    """Windows job object: if this app dies for any reason, Windows kills tun2socks too, which removes the
    adapter and its routes. Otherwise a crash could leave the PC routing everything into a dead tunnel."""
    import ctypes
    from ctypes import wintypes
    k = ctypes.windll.kernel32
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class EXT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    job = k.CreateJobObjectW(None, None)
    info = EXT()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
    return job, k


class Tunnel:
    def __init__(self, bin_dir=None, run=None, popen=subprocess.Popen, sleep=time.sleep):
        self.bin_dir = bin_dir or resource_dir()
        self._run = run or wifi._run
        self._popen = popen
        self._sleep = sleep
        self.proc = None
        self._job = None
        self._log_path = None
        self._secret = ""

    def _read_log(self):
        try:
            with open(self._log_path, errors="replace") as f:
                return f.read()[-400:].replace(self._secret, "***") if self._secret else f.read()[-400:]
        except OSError:
            return ""

    def start(self, gateway, port, user, password, iface):
        exe = os.path.join(self.bin_dir, "tun2socks.exe")
        if not os.path.exists(exe):
            raise TunnelError("tun2socks.exe is missing from the app.")
        self._secret = password
        diag.add_secret(password)
        fd, self._log_path = tempfile.mkstemp(prefix="sockstether-", suffix=".log")
        log = os.fdopen(fd, "w")
        kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if _WIN else {}
        kw["stdin"] = subprocess.DEVNULL
        diag.log("starting tun2socks: " + " ".join(tun2socks_args(exe, gateway, port, user, password, iface)))
        try:
            self.proc = self._popen(tun2socks_args(exe, gateway, port, user, password, iface),
                                    cwd=self.bin_dir, stdout=log, stderr=log, **kw)
        except OSError as e:
            raise TunnelError(f"Couldn't start the tunnel: {e}")
        finally:
            log.close()
        if _WIN:
            try:
                self._job, k = _kill_on_close_job()
                k.AssignProcessToJobObject(self._job, int(self.proc._handle))
            except Exception:
                pass  # best effort; stop() still cleans up on a normal exit

        try:
            for _ in range(40):  # up to ~20 s for the adapter to appear
                if self.proc.poll() is not None:
                    raise TunnelError("The tunnel program stopped right away: " + (self._read_log().strip() or
                                      "no details (is the app running as administrator?)"))
                rc, _out = self._run(["netsh", "interface", "ipv4", "show", "interface", f"name={TUN_NAME}"])
                if rc == 0:
                    break
                self._sleep(0.5)
            else:
                raise TunnelError("The virtual network adapter never appeared.")

            n = f"name={TUN_NAME}"
            steps = [
                (True, ["netsh", "interface", "ipv4", "set", "address", n, "source=static", f"addr={TUN_IP}", f"mask={TUN_MASK}"]),
                (False, ["netsh", "interface", "ipv4", "set", "dnsservers", n, "static", f"address={DNS[0]}", "register=none", "validate=no"]),
                (False, ["netsh", "interface", "ipv4", "add", "dnsservers", n, f"address={DNS[1]}", "index=2", "validate=no"]),
                (False, ["netsh", "interface", "ipv4", "set", "interface", n, "metric=1"]),
                (True, ["netsh", "interface", "ipv4", "add", "route", "0.0.0.0/0", TUN_NAME, TUN_IP, "metric=1"]),
            ]
            for must, cmd in steps:
                rc, out = self._run(cmd)
                if rc != 0 and must:
                    raise TunnelError(f"Network setup failed: {out.strip()}")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        p, self.proc = self.proc, None
        if p is not None:
            try:
                p.terminate()
                try:
                    p.wait(5)
                except Exception:
                    p.kill()
            except Exception:
                pass
            # the adapter (and its routes) disappear with the process; this is just belt and braces
            self._run(["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/0", TUN_NAME, TUN_IP])
        if self._log_path:
            try:
                os.remove(self._log_path)
            except OSError:
                pass
            self._log_path = None
