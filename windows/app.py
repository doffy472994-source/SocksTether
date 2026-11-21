"""SocksTether for Windows: pick your phone's network, connect, everything else is automatic.

Joins the phone's Wi-Fi Direct network, logs in to its SOCKS5 proxy (user "tether" + the Wi-Fi password) and
either tunnels ALL apps through it (virtual adapter, needs administrator) or, in browsers-only mode, sets the
Windows proxy through a local bridge. Disconnecting, closing the app or losing the phone restores everything.
"""
import asyncio
import atexit
import json
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import diag
import socksbridge
import sysproxy
import tunnel
import vault
import wifi

SOCKS_USER = "tether"
DEFAULT_PORT = 1080
CONFIG_PATH = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "SocksTether", "config.json")

# ---- look
FONT = "Segoe UI"
BG, CARD, CARD2, BORDER = "#0b1220", "#131c2e", "#1b2740", "#26334d"
ACCENT, TEXT, MUTED = "#38bdf8", "#e6edf7", "#8b9bb4"
GREEN, RED, AMBER = "#34d399", "#f87171", "#fbbf24"
KIND_COLOR = {"info": MUTED, "busy": AMBER, "ok": GREEN, "error": RED}


class UserError(Exception):
    pass


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            d = json.load(f)
        return {"port": int(d.get("port", DEFAULT_PORT)), "all_apps": bool(d.get("all_apps", True))}
    except (OSError, ValueError, TypeError):
        return {"port": DEFAULT_PORT, "all_apps": True}


def save_config(port, all_apps):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump({"port": port, "all_apps": all_apps}, f)
    except OSError:
        pass


def signal_text(pct):
    if not pct:
        return "–"
    bars = "▂▄▆█"[: 4 if pct >= 75 else 3 if pct >= 50 else 2 if pct >= 25 else 1]
    return f"{bars}  {pct}%"


def flat_button(parent, text, command, kind="primary", size=11):
    bg, fg, hover = {
        "primary": (ACCENT, "#04121f", "#7dd3fc"),
        "ghost": (CARD2, TEXT, "#243352"),
        "danger": (RED, "#1a0505", "#fca5a5"),
    }[kind]
    b = tk.Button(parent, text=text, command=command, bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
                  relief="flat", bd=0, padx=16, pady=8, font=(FONT, size, "bold"), cursor="hand2",
                  disabledforeground="#5b6b86", highlightthickness=0)
    b.bind("<Enter>", lambda e: b.config(bg=hover) if str(b["state"]) == "normal" else None)
    b.bind("<Leave>", lambda e: b.config(bg=bg) if str(b["state"]) == "normal" else None)
    b._base = bg
    return b


def set_enabled(btn, on):
    btn.config(state="normal" if on else "disabled", bg=btn._base if on else CARD2)


def card(parent, **pack):
    outer = tk.Frame(parent, bg=BORDER)
    outer.pack(fill="x", **pack)
    inner = tk.Frame(outer, bg=CARD, padx=14, pady=12)
    inner.pack(fill="both", expand=True, padx=1, pady=1)
    return inner


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, ssid):
        super().__init__(parent)
        self.result = None
        self.title("Wi-Fi password")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(parent)
        f = tk.Frame(self, bg=BG, padx=24, pady=20)
        f.pack()
        tk.Label(f, text="Enter the Wi-Fi password", font=(FONT, 14, "bold"), bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(f, text=ssid, font=(FONT, 10), bg=BG, fg=ACCENT).pack(anchor="w", pady=(2, 12))
        self.var = tk.StringVar()
        self.entry = tk.Entry(f, textvariable=self.var, show="•", width=34, font=(FONT, 12), bg=CARD2, fg=TEXT,
                              insertbackground=TEXT, relief="flat", highlightthickness=1,
                              highlightbackground=BORDER, highlightcolor=ACCENT)
        self.entry.pack(fill="x", ipady=7)
        self.show = tk.BooleanVar(value=False)
        tk.Checkbutton(f, text="Show password", variable=self.show, command=self._toggle, bg=BG, fg=MUTED,
                       selectcolor=CARD2, activebackground=BG, activeforeground=TEXT, bd=0,
                       highlightthickness=0, font=(FONT, 9)).pack(anchor="w", pady=(8, 0))
        tk.Label(f, text="It's saved on this PC (encrypted with your Windows account) once the connection works.",
                 font=(FONT, 9), bg=BG, fg=MUTED, wraplength=330, justify="left").pack(anchor="w", pady=(4, 14))
        row = tk.Frame(f, bg=BG)
        row.pack(fill="x")
        flat_button(row, "Cancel", self.destroy, "ghost").pack(side="right")
        flat_button(row, "Connect", self._ok, "primary").pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.grab_set()
        self.entry.focus_set()

    def _toggle(self):
        self.entry.config(show="" if self.show.get() else "•")

    def _ok(self):
        self.result = self.var.get()
        self.destroy()


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.proxy = sysproxy.SystemProxy()
        self.vault = vault.Vault()
        if self.proxy.has_pending_backup():  # a previous run crashed while the proxy was on
            self.proxy.restore()
        atexit.register(self._safety_restore)
        cfg = load_config()

        self.ssid = None
        self.bridge = None
        self.tunnel = None
        self.password = None
        self.busy = False
        self.sticky = False  # an error is showing: don't let the background scan overwrite it
        self.watch_stop = threading.Event()
        self.scan_now = threading.Event()
        self.closing = False

        root.title("SocksTether")
        root.geometry("480x720")
        root.minsize(440, 660)
        root.configure(bg=BG)
        root.report_callback_exception = self._on_tk_error

        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT, rowheight=40,
                        borderwidth=0, font=(FONT, 11))
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#04121f")])
        style.configure("Treeview.Heading", background=CARD, foreground=MUTED, borderwidth=0,
                        font=(FONT, 9, "bold"), relief="flat")
        style.map("Treeview.Heading", background=[("active", CARD)])

        body = tk.Frame(root, bg=BG, padx=20, pady=18)
        body.pack(fill="both", expand=True)

        head = tk.Frame(body, bg=BG)
        head.pack(fill="x", pady=(0, 14))
        tk.Label(head, text="SocksTether", font=(FONT, 22, "bold"), bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(head, text="Use your phone's mobile data on this PC", font=(FONT, 10), bg=BG, fg=MUTED).pack(anchor="w")

        # networks
        c = card(body, pady=(0, 12))
        top = tk.Frame(c, bg=CARD)
        top.pack(fill="x", pady=(0, 8))
        tk.Label(top, text="Networks nearby", font=(FONT, 11, "bold"), bg=CARD, fg=TEXT).pack(side="left")
        self.refresh_btn = flat_button(top, "⟳  Refresh", self.scan_now.set, "ghost", 9)
        self.refresh_btn.config(padx=10, pady=4)
        self.refresh_btn.pack(side="right")
        wrap = tk.Frame(c, bg=CARD)
        wrap.pack(fill="x")
        self.tree = ttk.Treeview(wrap, columns=("ssid", "signal", "saved"), show="headings", height=5,
                                 selectmode="browse")
        for col, title, w, anchor in (("ssid", "Network", 220, "w"), ("signal", "Signal", 90, "w"),
                                      ("saved", "Password", 80, "w")):
            self.tree.heading(col, text=title, anchor="w")
            self.tree.column(col, width=w, anchor=anchor, stretch=(col == "ssid"))
        self.tree.pack(fill="x")
        self.tree.bind("<Double-1>", lambda e: self.on_connect())
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_buttons())
        self.empty_lbl = tk.Label(wrap, text="Looking for SocksTether networks…\nStart SocksTether on your phone.",
                                  font=(FONT, 10), bg=CARD, fg=MUTED, justify="center")
        self.empty_lbl.place(relx=0.5, rely=0.55, anchor="center")

        # options
        c = card(body, pady=(0, 12))
        row = tk.Frame(c, bg=CARD)
        row.pack(fill="x")
        tk.Label(row, text="Proxy port", font=(FONT, 10), bg=CARD, fg=TEXT).pack(side="left")
        self.port_var = tk.StringVar(value=str(cfg["port"]))
        self.port_entry = tk.Entry(row, textvariable=self.port_var, width=7, font=(FONT, 11), bg=CARD2, fg=TEXT,
                                   insertbackground=TEXT, relief="flat", highlightthickness=1,
                                   highlightbackground=BORDER, highlightcolor=ACCENT, disabledbackground=CARD,
                                   disabledforeground=MUTED, justify="center")
        self.port_entry.pack(side="left", padx=10, ipady=4)
        self.all_apps_var = tk.BooleanVar(value=cfg["all_apps"])
        self.mode_chk = tk.Checkbutton(c, text="All apps, including Roblox and games", variable=self.all_apps_var,
                                       bg=CARD, fg=TEXT, selectcolor=CARD2, activebackground=CARD,
                                       activeforeground=TEXT, bd=0, highlightthickness=0, font=(FONT, 10),
                                       disabledforeground=MUTED)
        self.mode_chk.pack(anchor="w", pady=(10, 0))
        tk.Label(c, text="Needs administrator. Off = browsers and apps that follow the Windows proxy.",
                 font=(FONT, 9), bg=CARD, fg=MUTED, wraplength=400, justify="left").pack(anchor="w", padx=22)

        # actions
        self.connect_btn = flat_button(body, "Connect", self.on_connect, "primary", 13)
        self.connect_btn.pack(fill="x", pady=(0, 8), ipady=4)
        small = tk.Frame(body, bg=BG)
        small.pack(fill="x", pady=(0, 12))
        self.forget_btn = flat_button(small, "Forget saved password", self.on_forget, "ghost", 9)
        self.forget_btn.config(padx=10, pady=5)
        self.forget_btn.pack(side="left")
        log_btn = flat_button(small, "Open log", self.on_open_log, "ghost", 9)
        log_btn.config(padx=10, pady=5)
        log_btn.pack(side="right")

        # status
        c = card(body)
        srow = tk.Frame(c, bg=CARD)
        srow.pack(fill="x")
        self.dot = tk.Label(srow, text="●", font=(FONT, 12), bg=CARD, fg=MUTED)
        self.dot.pack(side="left", anchor="n", padx=(0, 8))
        self.status = tk.Label(srow, text="Looking for networks…", font=(FONT, 10), bg=CARD, fg=TEXT,
                               anchor="w", justify="left", wraplength=380)
        self.status.pack(side="left", fill="x", expand=True)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._update_buttons()
        threading.Thread(target=self._scan_loop, daemon=True).start()
        self._poll()

    # ---------------------------------------------------------------- UI helpers (main thread only)

    def set_status(self, text, kind="info"):
        self.sticky = kind == "error"
        self.dot.config(fg=KIND_COLOR.get(kind, MUTED))
        self.status.config(text=text, fg=TEXT if kind != "error" else RED)

    def _selected(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _update_buttons(self):
        sel = self._selected()
        set_enabled(self.forget_btn, bool(sel) and self.vault.has(sel) and not self.ssid and not self.busy)

    def _set_networks(self, nets):
        selected = self._selected()
        self.tree.delete(*self.tree.get_children())
        for n in nets:
            self.tree.insert("", "end", iid=n.ssid,
                             values=(n.ssid, signal_text(n.signal), "✓ saved" if self.vault.has(n.ssid) else ""))
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)
        elif len(nets) == 1:
            self.tree.selection_set(nets[0].ssid)
        if nets:
            self.empty_lbl.place_forget()
        else:
            self.empty_lbl.place(relx=0.5, rely=0.55, anchor="center")
        if not self.ssid and not self.busy and not self.sticky:
            self.set_status("Select your network and press Connect." if nets
                            else "No SocksTether networks found. Is it running on the phone?", "info")
        self._update_buttons()

    def _set_connected(self, ssid, gw, port, bridge, mode):
        self.ssid, self.bridge, self.busy = ssid, bridge, False
        self.connect_btn.config(text="Disconnect")
        self.connect_btn._base = RED
        self.connect_btn.config(bg=RED, fg="#1a0505", activebackground="#fca5a5", state="normal")
        self.tree.config(selectmode="none")
        self.port_entry.config(state="disabled")
        self.mode_chk.config(state="disabled")
        what = "All apps are going through the phone." if mode == "tunnel" else "Windows proxy is on (browsers and most apps)."
        self.set_status(f"Connected to {ssid}\n{what}", "ok")
        self.watch_stop.clear()
        threading.Thread(target=self._watchdog, args=(gw, port, self.password), daemon=True).start()
        self._update_buttons()

    def _set_disconnected(self, message=None, kind="info"):
        self.ssid = self.bridge = None
        self.busy = False
        self.connect_btn.config(text="Connect", bg=ACCENT, fg="#04121f", activebackground="#7dd3fc", state="normal")
        self.connect_btn._base = ACCENT
        self.tree.config(selectmode="browse")
        self.port_entry.config(state="normal")
        self.mode_chk.config(state="normal")
        self.set_status(message or "Disconnected. Your normal internet is back.", kind)
        if kind == "error":
            self._error_popup(message)
        self.scan_now.set()
        self._update_buttons()

    def _error_popup(self, message):
        messagebox.showerror("SocksTether", f"{message}\n\nDetails are saved in:\n{diag.path()}", parent=self.root)

    def _on_tk_error(self, exc, val, tb):
        diag.exc(f"UI error: {exc.__name__}: {val}")
        try:
            messagebox.showerror("SocksTether", f"Unexpected error: {val}\n\nDetails are saved in:\n{diag.path()}")
        except Exception:
            pass

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
                elif kind == "refresh":
                    self.scan_now.set()
                    self._update_buttons()
                elif kind == "autodisconnect":
                    if self.ssid and not self.busy:
                        self.disconnect(*args)
        except queue.Empty:
            pass
        if not self.closing:
            self.root.after(200, self._poll)

    # ---------------------------------------------------------------- actions

    def on_open_log(self):
        try:
            if not os.path.exists(diag.path()):
                diag.log("(log opened)")
            os.startfile(diag.path())
        except Exception:
            messagebox.showinfo("SocksTether", f"The log is at:\n{diag.path()}", parent=self.root)

    def on_forget(self):
        ssid = self._selected()
        if ssid:
            self.vault.forget(ssid)
            diag.log(f"forgot saved password for {ssid}")
            self.tree.set(ssid, "saved", "")
            self._update_buttons()

    def on_connect(self):
        if self.busy:
            return
        if self.ssid:
            self.disconnect()
            return
        ssid = self._selected()
        if not ssid:
            self.set_status("Select a network first.", "error")
            messagebox.showwarning("SocksTether", "Select a network from the list first.", parent=self.root)
            return
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showwarning("SocksTether", "Enter a valid proxy port (the default is 1080).", parent=self.root)
            return
        all_apps = self.all_apps_var.get()
        if all_apps and not tunnel.is_admin():
            self._error_popup("All-apps mode needs administrator rights. Close SocksTether and run it as administrator "
                              "(right-click → Run as administrator), or untick \"All apps\".")
            return
        pw = self.vault.get(ssid)
        from_vault = pw is not None
        if not pw:
            d = PasswordDialog(self.root, ssid)
            self.root.wait_window(d)
            pw = d.result
            if not pw:
                return
        save_config(port, all_apps)
        self.busy = True
        self.sticky = False
        set_enabled(self.connect_btn, False)
        set_enabled(self.forget_btn, False)
        self.set_status("Joining the network…", "busy")
        diag.log(f"connect: ssid={ssid} port={port} all_apps={all_apps} saved_password={from_vault}")
        threading.Thread(target=self._connect_worker, args=(ssid, pw, port, all_apps, from_vault), daemon=True).start()

    def disconnect(self, message=None, kind="info"):
        self.busy = True
        set_enabled(self.connect_btn, False)
        self.watch_stop.set()
        ssid, bridge = self.ssid, self.bridge
        self.set_status("Disconnecting…", "busy")

        def work():
            try:
                self._teardown(ssid, bridge)
            except Exception:
                diag.exc("teardown failed")
            self.q.put(("disconnected", message, kind))

        threading.Thread(target=work, daemon=True).start()

    def _teardown(self, ssid, bridge):
        try:
            if self.tunnel:  # first: removes the virtual adapter and its routes, so normal internet returns
                self.tunnel.stop()
                self.tunnel = None
            self.proxy.restore()  # and never keep pointing at a dead proxy
        finally:
            if bridge:
                bridge.stop()
            if ssid:
                wifi.disconnect(ssid)

    def on_close(self):
        self.closing = True
        self.watch_stop.set()
        if self.ssid or self.tunnel or self.proxy.has_pending_backup():
            try:
                self._teardown(self.ssid, self.bridge)
            except Exception:
                diag.exc("teardown on close failed")
        self.root.destroy()

    def _safety_restore(self):
        try:
            if self.tunnel:
                self.tunnel.stop()
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
                    diag.exc("scan failed")
            self.scan_now.wait(6)
            self.scan_now.clear()

    def _connect_worker(self, ssid, pw, port, all_apps, from_vault):
        bridge = None
        try:
            diag.add_secret(pw)
            wifi.connect(ssid, pw)
            self.q.put(("status", "Waiting for the phone to give this PC an address…", "busy"))
            gw = wifi.wait_for_gateway(ssid, 30)
            if not gw:
                hint = " If you changed the password on the phone, select the network and press “Forget saved password”." if from_vault else ""
                raise UserError("Couldn't join the network. Check the Wi-Fi password and that SocksTether is running on the phone." + hint)
            diag.log(f"joined {ssid}, gateway {gw}")
            self.q.put(("status", f"Checking the proxy at {gw}:{port}…", "busy"))
            try:
                asyncio.run(socksbridge.check_proxy(gw, port, SOCKS_USER, pw))
            except socksbridge.SocksAuthError:
                if from_vault:
                    self.vault.forget(ssid)
                raise UserError("The phone rejected the login. In SocksTether, turn on “Own Wi-Fi Direct network” and use "
                                "the same password." + (" The saved password was removed." if from_vault else ""))
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, socksbridge.SocksError) as e:
                diag.log(f"proxy check failed: {type(e).__name__}: {e}")
                raise UserError(f"Joined the network, but nothing answered at {gw}:{port}. "
                                "Is the proxy running on the phone, and is the port right?")
            self.password = pw
            if all_apps:
                alias = wifi.interface_alias_for(ssid)
                if not alias:
                    raise UserError("Couldn't find the Wi-Fi adapter for this network.")
                self.q.put(("status", "Starting the network tunnel for all apps…", "busy"))
                self.tunnel = tunnel.Tunnel()
                try:
                    self.tunnel.start(gw, port, SOCKS_USER, pw, alias)
                except tunnel.TunnelError as e:
                    raise UserError(str(e))
                mode, bridge = "tunnel", None
            else:
                bridge = socksbridge.Bridge(gw, port, SOCKS_USER, pw)
                self.proxy.enable(bridge.start())
                mode = "proxy"
            if not from_vault:
                try:
                    self.vault.set(ssid, pw)
                    diag.log(f"saved password for {ssid}")
                except Exception:
                    diag.exc("couldn't save password")
            self.q.put(("connected", ssid, gw, port, bridge, mode))
            self.q.put(("refresh",))
        except UserError as e:
            diag.log(f"connect failed: {e}")
            self._abort(ssid, bridge, str(e))
        except Exception as e:  # unexpected: still leave the PC in a clean state
            diag.exc("connect crashed")
            self._abort(ssid, bridge, f"Something went wrong: {e}")

    def _abort(self, ssid, bridge, message):
        try:
            self._teardown(ssid, bridge)
        except Exception:
            diag.exc("teardown after failure failed")
        self.q.put(("disconnected", message, "error"))

    def _watchdog(self, gw, port, password):
        """If the phone goes away, give the PC its normal internet back instead of a dead proxy/tunnel."""
        bad = 0
        while not self.watch_stop.wait(5):
            try:
                asyncio.run(socksbridge.check_proxy(gw, port, SOCKS_USER, password, timeout=4))
                bad = 0
            except Exception:
                bad += 1
            if bad >= 3 and not self.watch_stop.is_set():
                diag.log("watchdog: phone unreachable, disconnecting")
                self.q.put(("autodisconnect", "Lost the connection to the phone. Your normal internet is back.", "error"))
                return


def main():
    diag.start()
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
