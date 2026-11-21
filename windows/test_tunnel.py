import os
import tempfile
import unittest

import tunnel


class FakeProc:
    def __init__(self, dead=False):
        self.dead, self.terminated, self.killed = dead, False, False

    def poll(self):
        return 1 if self.dead else None

    def terminate(self): self.terminated = True
    def kill(self): self.killed = True
    def wait(self, t=None): return 0


def make(dead=False, adapter_after=0, fail_cmd=None):
    d = tempfile.mkdtemp()
    open(os.path.join(d, "tun2socks.exe"), "w").close()
    calls, popen_calls = [], []
    state = {"n": 0}

    def run(cmd, timeout=20):
        calls.append(cmd)
        if "show" in cmd and "interface" in cmd:
            state["n"] += 1
            return (0, "") if state["n"] > adapter_after else (1, "not found")
        if fail_cmd and fail_cmd in cmd:
            return 1, "boom"
        return 0, ""

    proc = FakeProc(dead)

    def popen(args, **kw):
        popen_calls.append((args, kw))
        return proc

    return tunnel.Tunnel(bin_dir=d, run=run, popen=popen, sleep=lambda s: None), calls, popen_calls, proc


class TunnelTests(unittest.TestCase):
    def test_args_encode_credentials_and_pin_interface(self):
        a = tunnel.tun2socks_args("t.exe", "192.168.49.1", 1080, "tether", "p@ss:w/rd", "Wi-Fi 2")
        self.assertEqual(a[a.index("-proxy") + 1], "socks5://tether:p%40ss%3Aw%2Frd@192.168.49.1:1080")
        self.assertEqual(a[a.index("-interface") + 1], "Wi-Fi 2")
        self.assertEqual(a[a.index("-device") + 1], "tun://SocksTether")

    def test_start_configures_adapter_dns_and_default_route_in_order(self):
        t, calls, pcalls, proc = make(adapter_after=3)
        t.start("192.168.49.1", 1080, "tether", "pw12345678", "Wi-Fi")
        flat = [" ".join(c) for c in calls]
        i_addr = next(i for i, c in enumerate(flat) if "set address" in c)
        i_route = next(i for i, c in enumerate(flat) if "add route 0.0.0.0/0 SocksTether 198.18.0.1 metric=1" in c)
        self.assertLess(i_addr, i_route)
        self.assertTrue(any("set dnsservers" in c and "1.1.1.1" in c for c in flat))
        self.assertTrue(any("set interface name=SocksTether metric=1" in c for c in flat))
        self.assertEqual(os.path.basename(pcalls[0][0][0]), "tun2socks.exe")
        self.assertFalse(proc.terminated)

    def test_early_exit_reports_and_hides_password(self):
        t, calls, pcalls, proc = make(dead=True)
        orig = t._popen

        def popen(args, **kw):  # tun2socks "logs" the password before dying
            kw["stdout"].write("fatal: cannot reach socks5://tether:topsecret99@x")
            kw["stdout"].flush()
            return orig(args, **kw)
        t._popen = popen
        with self.assertRaises(tunnel.TunnelError) as cm:
            t.start("192.168.49.1", 1080, "tether", "topsecret99", "Wi-Fi")
        self.assertIn("stopped right away", str(cm.exception))
        self.assertNotIn("topsecret99", str(cm.exception))

    def test_route_failure_cleans_up_process(self):
        t, calls, pcalls, proc = make(fail_cmd="route")
        with self.assertRaises(tunnel.TunnelError):
            t.start("192.168.49.1", 1080, "tether", "pw12345678", "Wi-Fi")
        self.assertTrue(proc.terminated)

    def test_stop_terminates_and_removes_route(self):
        t, calls, pcalls, proc = make()
        t.start("192.168.49.1", 1080, "tether", "pw12345678", "Wi-Fi")
        t.stop()
        self.assertTrue(proc.terminated)
        self.assertTrue(any("delete route" in " ".join(c) for c in calls))
        t.stop()  # idempotent

    def test_missing_binary(self):
        t = tunnel.Tunnel(bin_dir=tempfile.mkdtemp())
        with self.assertRaises(tunnel.TunnelError):
            t.start("g", 1, "u", "p", "i")


if __name__ == "__main__":
    unittest.main(verbosity=2)
