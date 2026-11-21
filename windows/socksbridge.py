"""Local HTTP/HTTPS proxy (127.0.0.1) that forwards everything through a SOCKS5 server.

Windows' system proxy setting only speaks HTTP, so this bridge lets browsers and most apps
use the phone's SOCKS5 proxy. Hostnames are sent to the phone to resolve (remote DNS).
"""
import asyncio
import ipaddress
import struct
import threading
from urllib.parse import urlsplit


class SocksError(Exception):
    pass


class SocksAuthError(SocksError):
    pass


_REPLIES = {1: "general failure", 2: "not allowed", 3: "network unreachable", 4: "host unreachable",
            5: "connection refused", 6: "TTL expired", 7: "command not supported", 8: "address type not supported"}


async def _login(r, w, user, password):
    offer = b"\x05\x02\x00\x02" if user is not None else b"\x05\x01\x00"
    w.write(offer)
    await w.drain()
    ver, method = await r.readexactly(2)
    if ver != 5 or method == 0xFF:
        raise SocksAuthError("proxy offered no acceptable login method")
    if method == 2:
        if user is None:
            raise SocksAuthError("proxy needs a login")
        u, p = user.encode(), password.encode()
        w.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await w.drain()
        _, status = await r.readexactly(2)
        if status != 0:
            raise SocksAuthError("proxy rejected the login")


async def _connect_cmd(r, w, host, port):
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        h = host.encode("idna")
        if len(h) > 255:
            raise SocksError("hostname too long")
        addr = b"\x03" + bytes([len(h)]) + h
    w.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    await w.drain()
    _, rep, _, atyp = await r.readexactly(4)
    if atyp == 1:
        await r.readexactly(6)
    elif atyp == 4:
        await r.readexactly(18)
    elif atyp == 3:
        n = (await r.readexactly(1))[0]
        await r.readexactly(n + 2)
    if rep != 0:
        raise SocksError(_REPLIES.get(rep, f"error {rep}"))


async def socks5_open(host, port, proxy_host, proxy_port, user=None, password=None, timeout=10):
    """Open a stream to host:port through the SOCKS5 proxy. host=None only logs in (used to verify)."""
    r, w = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port), timeout)
    try:
        await asyncio.wait_for(_login(r, w, user, password), timeout)
        if host is not None:
            await asyncio.wait_for(_connect_cmd(r, w, host, port), timeout)
    except BaseException:
        w.close()
        raise
    return r, w


async def check_proxy(proxy_host, proxy_port, user, password, timeout=6):
    """Raises SocksAuthError / SocksError / OSError / TimeoutError if the proxy isn't usable."""
    _, w = await socks5_open(None, 0, proxy_host, proxy_port, user, password, timeout)
    w.close()


async def _pump(r, w, peer):
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
        if w.can_write_eof():
            w.write_eof()
    except (OSError, asyncio.IncompleteReadError):
        for x in (w, peer):
            x.close()


async def _relay(cr, cw, sr, sw):
    try:
        await asyncio.gather(_pump(cr, sw, cw), _pump(sr, cw, sw))
    finally:
        sw.close()
        cw.close()


class Bridge:
    def __init__(self, proxy_host, proxy_port, user=None, password=None):
        self.proxy = (proxy_host, proxy_port, user, password)
        self.loop = None
        self.port = None
        self._server = None
        self._thread = None

    def start(self, listen_port=0):
        ready = threading.Event()
        err = []

        def run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self._server = self.loop.run_until_complete(
                    asyncio.start_server(self._handle, "127.0.0.1", listen_port))
                self.port = self._server.sockets[0].getsockname()[1]
            except OSError as e:
                err.append(e)
                ready.set()
                return
            ready.set()
            self.loop.run_forever()

        self._thread = threading.Thread(target=run, name="bridge", daemon=True)
        self._thread.start()
        ready.wait(5)
        if err:
            raise err[0]
        return self.port

    def stop(self):
        if self.loop is None:
            return

        def shutdown():
            if self._server:
                self._server.close()
            for t in asyncio.all_tasks(self.loop):
                t.cancel()
            self.loop.call_later(0.1, self.loop.stop)

        self.loop.call_soon_threadsafe(shutdown)
        if self._thread:
            self._thread.join(3)
        self.loop = None

    async def _handle(self, cr, cw):
        try:
            await self._serve(cr, cw)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
            pass
        except asyncio.CancelledError:
            pass
        finally:
            cw.close()

    async def _serve(self, cr, cw):
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 20)
        lines = head[:-4].split(b"\r\n")
        try:
            method, target, version = lines[0].decode("latin-1").split(" ", 2)
        except ValueError:
            cw.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        ph, pp, user, pw = self.proxy

        if method.upper() == "CONNECT":
            host, _, port = target.rpartition(":")
            host = host.strip("[]")
            try:
                sr, sw = await socks5_open(host, int(port), ph, pp, user, pw)
            except (SocksError, OSError, asyncio.TimeoutError, ValueError):
                cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await cw.drain()
            await _relay(cr, cw, sr, sw)
            return

        url = urlsplit(target)
        if not url.hostname:
            cw.write(b"HTTP/1.1 400 Bad Request\r\n\r\nThis is a proxy; use absolute URLs.\r\n")
            return
        path = (url.path or "/") + (("?" + url.query) if url.query else "")
        keep = [l for l in lines[1:] if l.split(b":", 1)[0].strip().lower()
                not in (b"proxy-connection", b"proxy-authorization", b"connection")]
        out = f"{method} {path} {version}\r\n".encode("latin-1") + b"\r\n".join(keep + [b"Connection: close"]) + b"\r\n\r\n"
        try:
            sr, sw = await socks5_open(url.hostname, url.port or 80, ph, pp, user, pw)
        except (SocksError, OSError, asyncio.TimeoutError):
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        sw.write(out)
        await sw.drain()
        await _relay(cr, cw, sr, sw)
