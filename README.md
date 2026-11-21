# SocksTether

Shares your phone's mobile data through a SOCKS5 proxy, over a Wi-Fi network the app creates itself
(a **Wi-Fi Direct** group, with the phone as group owner) instead of the system "Mobile Hotspot" toggle.

1. Tap **Start**. The app opens its own Wi-Fi Direct network (`DIRECT-ST-<name>`, name and password are yours to set on Android 10+) and a SOCKS5 server on the port you set (default 1080).
2. Join the hotspot from the other device (scan the QR code or type the shown password).
3. Point the other device at `socks5://user:pass@<phone-ip>:1080` (the app shows and copies the exact URL).
   - Browsers (Firefox: Settings → Network → Manual proxy → SOCKS v5, tick "Proxy DNS").
   - `curl --socks5-hostname user:pass@IP:1080 https://example.com`
   - Windows/macOS system settings don't speak SOCKS5 well; use Proxifier / per-app proxy settings.

Proxied traffic leaves the phone over the cellular network (toggle "Force mobile data") and appears as the
phone's own connections. Supports CONNECT and UDP ASSOCIATE, username/password auth, IPv4/IPv6 destinations,
remote DNS. Only private/LAN client addresses are accepted.

## Limits (Android, not the app)
- Wi-Fi Direct names must start with `DIRECT-xy-`, so the network name always begins `DIRECT-ST-`.
- Before Android 10 the platform picks the name/password; the app shows whatever it got.
- Wi-Fi must be switched on (Wi-Fi Direct needs the radio), and some phones drop their own Wi-Fi connection while a group is active.
- Location services must be on, and the Nearby devices (Android 13+) / Location permission granted.
- Clients reach the internet only through the proxy; the hotspot itself has no internet route.

## Build
`./gradlew :app:assembleDebug` (JDK 17 + Android SDK), or push to GitHub and download the APK artifact from
the *Build APK* workflow. `./gradlew :socks-core:test` runs the SOCKS5 server tests on the JVM.

## Windows app (`windows/`)
Pick the phone's `DIRECT-ST-…` network from the list, enter its password, done. The app joins the network,
logs in to the phone's proxy (user `tether` + the same Wi-Fi password), starts a local bridge and switches
the Windows system proxy to it. Disconnect, closing the app, or losing the phone puts your original proxy
settings back (a backup is kept on disk, so even a crash is repaired next launch).

- Needs the phone's **Own Wi-Fi Direct network** switch on (it makes the proxy login automatic). Default port 1080; change it in the app if you changed it on the phone.
- Windows' system proxy is HTTP-only, so apps that ignore the system proxy (some games/launchers/CLI tools) aren't covered. Browsers, Windows Update, Store, most desktop apps are.
- Build: push to GitHub, download `SocksTether.exe` from the *Build Windows app* workflow. Or run `python app.py` (Python 3.10+, no dependencies). Tests: `python -m unittest test_core -v` inside `windows/`.
