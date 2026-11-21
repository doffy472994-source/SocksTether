package dev.itsricky.sockstether

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.ServiceCompat
import dev.itsricky.sockstether.socks.Credentials
import dev.itsricky.sockstether.socks.DefaultOutbound
import dev.itsricky.sockstether.socks.Outbound
import dev.itsricky.sockstether.socks.Socks5Server
import java.io.IOException

class TetherService : Service() {
    private var server: Socks5Server? = null
    private var cellular: CellularOutbound? = null
    private var hotspot: HotspotController? = null
    private var wake: PowerManager.WakeLock? = null
    private var cfg = Config()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> if (!TetherState.running.value) startAll() else Unit
            else -> shutdown() // ACTION_STOP, or a null restart intent
        }
        return START_NOT_STICKY
    }

    private fun startAll() {
        createChannel()
        ServiceCompat.startForeground(
            this, NOTIF_ID, notification("Starting…"),
            if (android.os.Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE else 0,
        )
        cfg = ConfigStore(this).load()
        if (cfg.hotspot && !(ConfigStore.validHotspotName(cfg.hotspotName) && ConfigStore.validHotspotPass(cfg.hotspotPass))) {
            TetherState.log("Refusing to start: invalid hotspot name or password")
            shutdown(); return
        }
        if (!cfg.hotspot && cfg.auth && (cfg.user.isEmpty() || cfg.pass.isEmpty())) {
            TetherState.log("Refusing to start: authentication is on but username or password is empty")
            shutdown(); return
        }

        val outbound: Outbound = if (cfg.cellular) CellularOutbound(this).also { it.start(); cellular = it } else DefaultOutbound()
        val srv = Socks5Server(
            port = cfg.port,
            outbound = outbound,
            credentials = cfg.proxyCredentials()?.let { (u, p) -> Credentials(u, p) },
            clientAllowed = NetInfo::isLocalClient,
            log = TetherState::log,
        )
        try {
            srv.start()
        } catch (e: IOException) {
            TetherState.log("Couldn't listen on port ${cfg.port}: ${e.message}")
            shutdown(); return
        }
        server = srv
        TetherState.server = srv
        TetherState.running.value = true
        wake = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sockstether:proxy").apply { acquire() }
        TetherState.log("SOCKS5 proxy listening on port ${cfg.port}")
        refreshNotification()

        if (cfg.hotspot) {
            hotspot = HotspotController(this).also {
                it.start(cfg.hotspotName, cfg.hotspotPass) { st ->
                    TetherState.hotspot.value = st
                    when (st) {
                        is HotspotStatus.On -> TetherState.log("Hotspot up: ${st.ssid}")
                        is HotspotStatus.Failed -> TetherState.log("Hotspot failed: ${st.reason}")
                        else -> {}
                    }
                    refreshNotification()
                }
            }
        } else {
            TetherState.hotspot.value = HotspotStatus.Off
        }
    }

    private fun refreshNotification() {
        val ip = NetInfo.localAddresses().firstOrNull { it.clientFacing }?.ip
        val text = if (ip != null) "SOCKS5 on $ip:${cfg.port}" else "SOCKS5 on port ${cfg.port}"
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification(text))
    }

    private fun shutdown() {
        runCatching { server?.stop() }
        runCatching { hotspot?.stop() }
        runCatching { cellular?.close() }
        runCatching { wake?.takeIf { it.isHeld }?.release() }
        server = null; hotspot = null; cellular = null; wake = null
        TetherState.server = null
        TetherState.running.value = false
        TetherState.hotspot.value = HotspotStatus.Off
        TetherState.log("Stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        if (TetherState.running.value) shutdown()
        super.onDestroy()
    }

    private fun createChannel() {
        val ch = NotificationChannel(CHANNEL, "Proxy status", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, TetherService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_tether)
            .setContentTitle("SocksTether")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_stat_tether), "Stop", stop).build())
            .build()
    }

    companion object {
        const val ACTION_START = "dev.itsricky.sockstether.START"
        const val ACTION_STOP = "dev.itsricky.sockstether.STOP"
        private const val CHANNEL = "proxy"
        private const val NOTIF_ID = 1
    }
}
