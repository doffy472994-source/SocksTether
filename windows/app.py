"""SocksTether for Windows: pick a SocksTether network, enter its password, everything else is automatic.

Joins the phone's Wi-Fi Direct network, logs in to its SOCKS5 proxy (user "tether" + the Wi-Fi password),
starts a local HTTP->SOCKS5 bridge and points the Windows system proxy at it. Disconnecting (or closing
the app, or losing the phone) restores your original proxy settings.
"""
import asyncio
import atexit
import json
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk, simpledialog

import socksbridge
import sysproxy
import wifi

SOCKS_USER = "tether"
DEFAULT_PORT = 1080
CONFIG_PATH = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "SocksTether", "config.json")


class UserError(Exception):
    pass


def load_port():
    try:
        with open(CONFIG_PATH) as f:
            return int(json.load(f).get("port", DEFAULT_PORT))
    except (OSError, ValueError, TypeError):
        return DEFAULT_PORT


def save_port(port):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump({"port": port}, f)
    except OSError:
        pass


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.proxy = sysproxy.SystemProxy()
        if self.proxy.has_pending_backup():  # a previous run crashed while the proxy was on
            self.proxy.restore()
        atexit.register(self._safety_restore)

        self.ssid = None
        self.bridge = None
        self.busy = False
        self.watch_stop = threading.Event()
        self.scan_now = threading.Event()
        self.closing = False

        root.title("SocksTether")
        root.geometry("420x430")
        root.minsize(380, 380)
        frm = ttk.Frame(root, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="SocksTether networks nearby", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(frm, text="Start SocksTether on your phone, then pick its network.",
                  foreground="#666").pack(anchor="w", pady=(0, 8))

        self.tree = ttk.Treeview(frm, columns=("ssid", "signal"), show="headings", height=7, selectmode="browse")
        self.tree.heading("ssid", text="Network")
        self.tree.heading("signal", text="Signal")
        self.tree.column("ssid", width=250)
        self.tree.column("signal", width=70, anchor="e")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.on_connect())

        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(10, 0))
        ttk.Label(row, text="Proxy port").pack(side="left")
        self.port_var = tk.StringVar(value=str(load_port()))
        self.port_entry = ttk.Entry(row, textvariable=self.port_var, width=7)
        self.port_entry.pack(side="left", padx=6)
        self.refresh_btn = ttk.Button(row, text="Refresh", command=self.scan_now.set)
        self.refresh_btn.pack(side="right")
        self.connect_btn = ttk.Button(row, text="Connect", command=self.on_connect)
        self.connect_btn.pack(side="right", padx=6)

        self.status = tk.Label(frm, text="Looking for networks…", anchor="w", justify="left", wraplength=380)
        self.status.pack(fill="x", pady=(12, 0))

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        threading.Thread(target=self._scan_loop, daemon=True).start()
        self._poll()

    # ---------------------------------------------------------------- UI helpers (main thread only)

    def set_status(self, text, color="#222"):
        self.status.config(text=text, fg=color)

    def _set_networks(self, nets):
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for n in nets:
            self.tree.insert("", "end", iid=n.ssid, values=(n.ssid, f"{n.signal}%" if n.signal else "–"))
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected[0])
        elif len(nets) == 1:
            self.tree.selection_set(nets[0].ssid)
        if not self.ssid and not self.busy:
            self.set_status("Select your network and press Connect." if nets else
                            "No SocksTether networks found. Is it running on the phone?")

    def _set_connected(self, ssid, gw, port, bridge):
        self.ssid, self.bridge, self.busy = ssid, bridge, False
        self.connect_btn.config(text="Disconnect", state="normal")
        self.tree.config(selectmode="none")
        self.port_entry.config(state="disabled")
        self.set_status(f"Connected to {ssid}\nProxy {gw}:{port} · Windows proxy is on.", "#0a7a2f")
        self.watch_stop.clear()
        threading.Thread(target=self._watchdog, args=(gw, port, bridge.proxy[3]), daemon=True).start()

    def _set_disconnected(self, message=None, color="#222"):
        self.ssid = self.bridge = None
        self.busy = False
        self.connect_btn.config(text="Connect", state="normal")
        self.tree.config(selectmode="browse")
        self.port_entry.config(state="normal")
        self.set_status(message or "Disconnected. Your original proxy settings are back.", color)
        self.scan_now.set()

    def _poll(self):
        try:
            while True:
                kind, *args = self.q.get_nowait()
                if kind == "nets":
                    self._set_networks(args[0])
                elif kind == "status":
                    self.set_status(*args)
                elif kind == "connected":
                    self._set_connected(*args)
                elif kind == "disconnected":
                    self._set_disconnected(*args)
                elif kind == "autodisconnect":
                    if self.ssid and not self.busy:
                        self.disconnect(*args)
        except queue.Empty:
            pass
        if not self.closing:
            self.root.after(200, self._poll)

    # ---------------------------------------------------------------- actions

    def on_connect(self):
        if self.busy:
            return
        if self.ssid:
            self.disconnect()
            return
        sel = self.tree.selection()
        if not sel:
            self.set_status("Select a network first.", "#b00020")
            return
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.set_status("Enter a valid proxy port (default 1080).", "#b00020")
            return
        ssid = sel[0]
        pw = simpledialog.askstring("Wi-Fi password", f"Password for {ssid}", show="*", parent=self.root)
        if not pw:
            return
        save_port(port)
        self.busy = True
        self.connect_btn.config(state="disabled")
        self.set_status("Joining the network…")
        threading.Thread(target=self._connect_worker, args=(ssid, pw, port), daemon=True).start()

    def disconnect(self, message=None, color="#222"):
        self.busy = True
        self.connect_btn.config(state="disabled")
        self.watch_stop.set()
        ssid, bridge = self.ssid, self.bridge
        self.set_status("Disconnecting…")

        def work():
            self._teardown(ssid, bridge)
            self.q.put(("disconnected", message, color))

        threading.Thread(target=work, daemon=True).start()

    def _teardown(self, ssid, bridge):
        try:
            self.proxy.restore()  # first, so the PC never keeps pointing at a dead proxy
        finally:
            if bridge:
                bridge.stop()
            if ssid:
                wifi.disconnect(ssid)

    def on_close(self):
        self.closing = True
        self.watch_stop.set()
        if self.ssid or self.proxy.has_pending_backup():
            try:
                self._teardown(self.ssid, self.bridge)
            except Exception:
                pass
        self.root.destroy()

    def _safety_restore(self):
        try:
            self.proxy.restore()
        except Exception:
            pass

    # ---------------------------------------------------------------- background threads

    def _scan_loop(self):
        while not self.closing:
            if not self.ssid and not self.busy:
                try:
                    self.q.put(("nets", wifi.scan()))
                except Exception:
                    pass
            self.scan_now.wait(6)
            self.scan_now.clear()

    def _connect_worker(self, ssid, pw, port):
        bridge = None
        try:
            wifi.connect(ssid, pw)
            self.q.put(("status", "Waiting for the phone to give this PC an address…", "#222"))
            gw = wifi.wait_for_gateway(ssid, 30)
            if not gw:
                raise UserError("Couldn't join the network. Check the Wi-Fi password and that SocksTether is running on the phone.")
            self.q.put(("status", f"Checking the proxy at {gw}:{port}…", "#222"))
            try:
                asyncio.run(socksbridge.check_proxy(gw, port, SOCKS_USER, pw))
            except socksbridge.SocksAuthError:
                raise UserError("The phone rejected the login. In SocksTether, turn on 'Own Wi-Fi Direct network' and use the same password.")
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, socksbridge.SocksError):
                raise UserError(f"Joined the network, but nothing answered at {gw}:{port}. Is the proxy running, and is the port right?")
            bridge = socksbridge.Bridge(gw, port, SOCKS_USER, pw)
            local_port = bridge.start()
            self.proxy.enable(local_port)
            self.q.put(("connected", ssid, gw, port, bridge))
        except UserError as e:
            self._abort(ssid, bridge, str(e))
        except Exception as e:  # unexpected: still leave the PC in a clean state
            self._abort(ssid, bridge, f"Something went wrong: {e}")

    def _abort(self, ssid, bridge, message):
        try:
            self._teardown(ssid, bridge)
        except Exception:
            pass
        self.q.put(("disconnected", message, "#b00020"))

    def _watchdog(self, gw, port, password):
        """If the phone goes away, give the PC its normal internet back instead of a dead proxy."""
        bad = 0
        while not self.watch_stop.wait(5):
            try:
                asyncio.run(socksbridge.check_proxy(gw, port, SOCKS_USER, password, timeout=4))
                bad = 0
            except Exception:
                bad += 1
            if bad >= 3 and not self.watch_stop.is_set():
                self.q.put(("autodisconnect", "Lost the connection to the phone. Normal internet restored.", "#b00020"))
                return


def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
