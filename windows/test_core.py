import asyncio
import json
import os
import socket
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

import socksbridge
import sysproxy
import wifi

EN = """
Interface name : Wi-Fi
There are 4 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 91%
         Radio type         : 802.11ac

SSID 2 : DIRECT-ST-Ricky
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    BSSID 1                 : aa:bb:cc:dd:ee:02
         Signal             : 62%
    BSSID 2                 : aa:bb:cc:dd:ee:03
         Signal             : 88%

SSID 3 : DIRECT-xy-Printer
    BSSID 1                 : aa:bb:cc:dd:ee:04
         Signal             : 99%

SSID 4 : DIRECT-ST-Alt
    BSSID 1                 : aa:bb:cc:dd:ee:05
         Signal             : 40%
"""

ES = """
Nombre de interfaz : Wi-Fi
Hay 2 redes visibles actualmente.

SSID 1 : DIRECT-ST-Casa
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    BSSID 1                 : aa:bb:cc:dd:ee:02
         Señal              : 75%

SSID 2 :
    BSSID 1                 : aa:bb:cc:dd:ee:09
         Señal              : 20%
"""


class WifiParsing(unittest.TestCase):
    def test_filters_orders_and_takes_best_signal(self):
        nets = wifi.socks_networks(EN)
        self.assertEqual([(n.ssid, n.signal) for n in nets], [("DIRECT-ST-Ricky", 88), ("DIRECT-ST-Alt", 40)])

    def test_works_on_spanish_windows(self):
        self.assertEqual([(n.ssid, n.signal) for n in wifi.socks_networks(ES)], [("DIRECT-ST-Casa", 75)])

    def test_hidden_ssid_ignored_and_all_networks_parsed(self):
        self.assertEqual({n.ssid for n in wifi.parse_networks(ES)}, {"DIRECT-ST-Casa"})
        self.assertEqual(len(wifi.parse_networks(EN)), 4)

    def test_profile_xml_is_valid_and_escapes_password(self):
        pw = 'p&ss<w>"o\'rd1'
        root = ET.fromstring(wifi.profile_xml("DIRECT-ST-A&B", pw))
        ns = {"n": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        self.assertEqual(root.find("n:MSM/n:security/n:sharedKey/n:keyMaterial", ns).text, pw)
        self.assertEqual(root.find("n:name", ns).text, "DIRECT-ST-A&B")
        self.assertEqual(root.find("n:MSM/n:security/n:authEncryption/n:authentication", ns).text, "WPA2PSK")


class FakeRegistry:
    def __init__(self, values):
        self.v = dict(values)
        self.notified = 0

    def get(self, n):
        return self.v.get(n)

    def set(self, n, value, typ):
        self.v[n] = [value, typ]

    def delete(self, n):
        self.v.pop(n, None)

    def notify(self):
        self.notified += 1


class SystemProxyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "sub", "backup.json")

    def test_enable_then_restore_returns_original(self):
        orig = {"ProxyEnable": [0, 4], "ProxyServer": ["corp:8080", 1], "AutoConfigURL": ["http://pac/x.pac", 1]}
        reg = FakeRegistry(orig)
        sp = sysproxy.SystemProxy(reg, self.path)
        sp.enable(8899)
        self.assertEqual(reg.v["ProxyServer"], ["127.0.0.1:8899", 1])
        self.assertEqual(reg.v["ProxyEnable"], [1, 4])
        self.assertNotIn("AutoConfigURL", reg.v)
        self.assertTrue(sp.restore())
        self.assertEqual(reg.v, orig)  # values that didn't exist before are removed again
        self.assertFalse(os.path.exists(self.path))

    def test_crash_recovery_keeps_the_real_original(self):
        orig = {"ProxyEnable": [0, 4]}
        reg = FakeRegistry(orig)
        sysproxy.SystemProxy(reg, self.path).enable(1111)
        # app crashed; new run enables again, then restores. Backup must still hold the user's real settings.
        sp2 = sysproxy.SystemProxy(reg, self.path)
        self.assertTrue(sp2.has_pending_backup())
        sp2.enable(2222)
        sp2.restore()
        self.assertEqual(reg.v, orig)

    def test_restore_without_backup_is_noop(self):
        reg = FakeRegistry({"ProxyEnable": [1, 4]})
        self.assertFalse(sysproxy.SystemProxy(reg, self.path).restore())
        self.assertEqual(reg.v, {"ProxyEnable": [1, 4]})


class FakeSocksPhone:
    """Minimal SOCKS5 server with user/pass auth. Resolves 'phone.test' to loopback to prove remote DNS."""

    def __init__(self, user, password):
        self.user, self.password = user, password
        self.requested = []
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(asyncio.start_server(self.handle, "127.0.0.1", 0))
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()
            self.loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
        ready.wait(5)

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)

    async def handle(self, r, w):
        try:
            _, n = await r.readexactly(2)
            methods = await r.readexactly(n)
            if 2 not in methods:
                w.write(b"\x05\xff"); return
            w.write(b"\x05\x02")
            await r.readexactly(1)
            u = await r.readexactly((await r.readexactly(1))[0])
            p = await r.readexactly((await r.readexactly(1))[0])
            ok = u.decode() == self.user and p.decode() == self.password
            w.write(b"\x01" + (b"\x00" if ok else b"\x01"))
            if not ok:
                return
            await w.drain()
            hdr = await r.readexactly(4)
            if hdr[3] == 1:
                host = socket.inet_ntoa(await r.readexactly(4))
            elif hdr[3] == 3:
                host = (await r.readexactly((await r.readexactly(1))[0])).decode()
            else:
                w.write(b"\x05\x08\x00\x01" + bytes(6)); return
            port = int.from_bytes(await r.readexactly(2), "big")
            self.requested.append((hdr[3], host, port))
            target = "127.0.0.1" if host == "phone.test" else host
            try:
                tr, tw = await asyncio.open_connection(target, port)
            except OSError:
                w.write(b"\x05\x05\x00\x01" + bytes(6)); return
            w.write(b"\x05\x00\x00\x01" + bytes(6))
            await socksbridge._relay(r, w, tr, tw)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            w.close()


class EchoServer:
    def __init__(self, http=False):
        self.s = socket.socket(); self.s.bind(("127.0.0.1", 0)); self.s.listen(8)
        self.port = self.s.getsockname()[1]
        self.http = http
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.s.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        with c:
            if self.http:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = c.recv(4096)
                    if not chunk: return
                    data += chunk
                self.last_request = data
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            else:
                while True:
                    d = c.recv(4096)
                    if not d: return
                    c.sendall(d)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.phone = FakeSocksPhone("tether", "s3cret-pass")
        self.bridge = socksbridge.Bridge("127.0.0.1", self.phone.port, "tether", "s3cret-pass")
        self.port = self.bridge.start()

    def tearDown(self):
        self.bridge.stop(); self.phone.close()

    def _client(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        return s

    def test_connect_tunnel_echo_with_remote_dns(self):
        echo = EchoServer()
        s = self._client()
        s.sendall(f"CONNECT phone.test:{echo.port} HTTP/1.1\r\nHost: phone.test\r\n\r\n".encode())
        reply = b""
        while b"\r\n\r\n" not in reply:
            reply += s.recv(1024)
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"))
        s.sendall(b"ping through tunnel")
        self.assertEqual(s.recv(1024), b"ping through tunnel")
        s.close()
        self.assertIn((3, "phone.test", echo.port), self.phone.requested)  # hostname went to the phone unresolved

    def test_plain_http_get_is_rewritten_and_relayed(self):
        web = EchoServer(http=True)
        s = self._client()
        s.sendall(f"GET http://127.0.0.1:{web.port}/a/b?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  f"Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic zzz\r\nConnection: keep-alive\r\n\r\n".encode())
        body = b""
        while True:
            d = s.recv(4096)
            if not d: break
            body += d
        self.assertTrue(body.startswith(b"HTTP/1.1 200"))
        self.assertTrue(body.endswith(b"hello"))
        req = web.last_request.decode()
        self.assertTrue(req.startswith("GET /a/b?x=1 HTTP/1.1\r\n"))
        self.assertNotIn("Proxy-", req)
        self.assertIn("Connection: close", req)
        self.assertNotIn("keep-alive", req)

    def test_unreachable_target_gives_502(self):
        dead = socket.socket(); dead.bind(("127.0.0.1", 0)); port = dead.getsockname()[1]; dead.close()
        s = self._client()
        s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        self.assertTrue(s.recv(1024).startswith(b"HTTP/1.1 502"))

    def test_large_transfer_both_ways(self):
        echo = EchoServer()
        s = self._client()
        s.sendall(f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\n\r\n".encode())
        while b"\r\n\r\n" not in (hdr := s.recv(1024)): pass
        blob = os.urandom(400_000)
        threading.Thread(target=lambda: s.sendall(blob), daemon=True).start()
        got = b""
        while len(got) < len(blob):
            got += s.recv(65536)
        self.assertEqual(got, blob)


class CheckProxyTests(unittest.TestCase):
    def test_good_and_bad_login(self):
        phone = FakeSocksPhone("tether", "right-pass")
        try:
            asyncio.run(socksbridge.check_proxy("127.0.0.1", phone.port, "tether", "right-pass"))
            with self.assertRaises(socksbridge.SocksAuthError):
                asyncio.run(socksbridge.check_proxy("127.0.0.1", phone.port, "tether", "wrong"))
        finally:
            phone.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
