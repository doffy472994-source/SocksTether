package dev.itsricky.sockstether

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Handler
import android.os.Looper

/**
 * Our own access point built as a Wi-Fi Direct group (we are the group owner). Ordinary Wi-Fi
 * devices can join it like a normal network. It is separate from Android's system "Mobile Hotspot".
 * On Android 10+ we choose the name and password; before that the platform picks them.
 */
class HotspotController(ctx: Context) {
    private val app = ctx.applicationContext
    private val wpm: WifiP2pManager? = app.getSystemService(WifiP2pManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private var channel: WifiP2pManager.Channel? = null

    @SuppressLint("MissingPermission")
    fun start(nameSuffix: String, passphrase: String, onState: (HotspotStatus) -> Unit) {
        val mgr = wpm
        if (mgr == null) { onState(HotspotStatus.Failed("Wi-Fi Direct isn't supported on this device.")); return }
        onState(HotspotStatus.Starting)
        val ch = mgr.initialize(app, Looper.getMainLooper(), null)
        if (ch == null) { onState(HotspotStatus.Failed("Couldn't open Wi-Fi Direct. Is Wi-Fi turned on?")); return }
        channel = ch
        try {
            // Clear any stale group first so createGroup doesn't come back BUSY.
            mgr.removeGroup(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() = create(mgr, ch, nameSuffix, passphrase, onState)
                override fun onFailure(reason: Int) = create(mgr, ch, nameSuffix, passphrase, onState)
            })
        } catch (e: SecurityException) {
            onState(HotspotStatus.Failed(PERMISSION_MSG))
        }
    }

    @SuppressLint("MissingPermission")
    private fun create(mgr: WifiP2pManager, ch: WifiP2pManager.Channel, suffix: String, pass: String, onState: (HotspotStatus) -> Unit) {
        val listener = object : WifiP2pManager.ActionListener {
            override fun onSuccess() = readGroup(mgr, ch, onState, attemptsLeft = 8)
            override fun onFailure(reason: Int) = onState(HotspotStatus.Failed(describe(reason)))
        }
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                val cfg = WifiP2pConfig.Builder()
                    .setNetworkName("DIRECT-ST-$suffix")
                    .setPassphrase(pass)
                    .enablePersistentMode(false)
                    .setGroupOperatingBand(WifiP2pConfig.GROUP_OWNER_BAND_AUTO)
                    .build()
                mgr.createGroup(ch, cfg, listener)
            } else {
                mgr.createGroup(ch, listener)
            }
        } catch (e: SecurityException) {
            onState(HotspotStatus.Failed(PERMISSION_MSG))
        } catch (e: IllegalArgumentException) {
            onState(HotspotStatus.Failed("Invalid hotspot name or password: ${e.message}"))
        }
    }

    /** The group info can lag a moment behind createGroup's success callback, so retry briefly. */
    @SuppressLint("MissingPermission")
    private fun readGroup(mgr: WifiP2pManager, ch: WifiP2pManager.Channel, onState: (HotspotStatus) -> Unit, attemptsLeft: Int) {
        try {
            mgr.requestGroupInfo(ch) { g ->
                if (g != null && g.networkName != null) {
                    onState(HotspotStatus.On(g.networkName, g.passphrase.orEmpty()))
                } else if (attemptsLeft > 0) {
                    main.postDelayed({ readGroup(mgr, ch, onState, attemptsLeft - 1) }, 500)
                } else {
                    onState(HotspotStatus.Failed("Group was created but its details couldn't be read."))
                }
            }
        } catch (e: SecurityException) {
            onState(HotspotStatus.Failed(PERMISSION_MSG))
        }
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        val mgr = wpm ?: return
        val ch = channel ?: return
        channel = null
        val closeChannel = { if (Build.VERSION.SDK_INT >= 27) runCatching { ch.close() } }
        try {
            mgr.removeGroup(ch, object : WifiP2pManager.ActionListener {
                override fun onSuccess() { closeChannel() }
                override fun onFailure(reason: Int) { closeChannel() }
            })
        } catch (e: SecurityException) {
            closeChannel()
        }
    }

    private fun describe(reason: Int) = when (reason) {
        WifiP2pManager.P2P_UNSUPPORTED -> "Wi-Fi Direct isn't supported on this device."
        WifiP2pManager.BUSY -> "Wi-Fi Direct is busy (another group or session is active). Try again in a moment."
        WifiP2pManager.NO_SERVICE_REQUESTS -> "Wi-Fi Direct service unavailable."
        else -> "Couldn't create the Wi-Fi Direct group. Make sure Wi-Fi and Location are turned on."
    }

    private companion object {
        const val PERMISSION_MSG = "Permission denied. Allow Nearby devices (or Location) and make sure Location is switched on."
    }
}
