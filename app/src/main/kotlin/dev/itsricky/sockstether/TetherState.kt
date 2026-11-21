package dev.itsricky.sockstether

import dev.itsricky.sockstether.socks.Socks5Server
import kotlinx.coroutines.flow.MutableStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

sealed interface HotspotStatus {
    data object Off : HotspotStatus
    data object Starting : HotspotStatus
    data class On(val ssid: String, val password: String) : HotspotStatus
    data class Failed(val reason: String) : HotspotStatus
}

data class Stats(val connections: Int = 0, val up: Long = 0, val down: Long = 0)

/** Service and UI live in the same process, so a process-wide holder is the simplest bridge. */
object TetherState {
    val running = MutableStateFlow(false)
    val hotspot = MutableStateFlow<HotspotStatus>(HotspotStatus.Off)
    val logLines = MutableStateFlow<List<String>>(emptyList())
    @Volatile var server: Socks5Server? = null

    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun log(msg: String) {
        val line = "${fmt.format(Date())}  $msg"
        logLines.value = (logLines.value + line).takeLast(60)
    }

    fun stats(): Stats = server?.let { Stats(it.activeConnections.get(), it.bytesUp.get(), it.bytesDown.get()) } ?: Stats()
}
