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
Pick the phone's `DIRECT-ST-…` network from the list, enter its password, done. The app joins the network and
logs in to the phone's proxy (user `tether` + the same Wi-Fi password).

Two modes (tick box in the app):
- **All apps (default, needs administrator):** creates a virtual network adapter (Wintun) and uses tun2socks to send
  *everything* (TCP and UDP, so Roblox and other games) through the phone's SOCKS5 proxy. UDP goes through
  SOCKS5 UDP ASSOCIATE, which the phone app supports. DNS is set to 1.1.1.1 / 8.8.8.8 on the adapter.
- **Browsers only:** sets the Windows proxy via a local HTTP→SOCKS5 bridge; no admin, but apps that ignore the
  system proxy (Roblox, games, many launchers) aren't covered.

Disconnecting, closing the app, losing the phone, or even crashing puts everything back (the tunnel process is
tied to the app by a Windows job object; the system-proxy backup is repaired on next launch).
Bundled third-party binaries (downloaded at build time, version-pinned and SHA-256 checked in CI): tun2socks v2.6.0 (MIT), Wintun 0.14.1.
IPv6 isn't tunnelled: if your PC has its own IPv6 internet, IPv6-only traffic would bypass the phone.

Build: push to GitHub (the *Build Windows app* workflow publishes `SocksTether.exe` to the `builds-windows` branch).
Tests: `python -m unittest test_core test_tunnel -v` inside `windows/`.
