package dev.itsricky.sockstether

import android.content.Context
import java.security.SecureRandom

data class Config(
    val port: Int = 1080,
    val auth: Boolean = true,
    val user: String = "tether",
    val pass: String = "",
    /** Send outbound traffic over the mobile-data network specifically. */
    val cellular: Boolean = true,
    /** Create our own Wi-Fi Direct group. Off = just listen on whatever network is up. */
    val hotspot: Boolean = true,
    /** Shown to clients as DIRECT-ST-<hotspotName>. */
    val hotspotName: String = "SocksTether",
    val hotspotPass: String = "",
) {
    /**
     * With our own Wi-Fi Direct network on, the proxy login is fixed to "tether" + the Wi-Fi password,
     * so the Windows app (and anything else) needs only that one password. Otherwise the manual login applies.
     */
    fun proxyCredentials(): Pair<String, String>? = when {
        hotspot -> HOTSPOT_USER to hotspotPass
        auth -> user to pass
        else -> null
    }

    companion object { const val HOTSPOT_USER = "tether" }
}

class ConfigStore(ctx: Context) {
    private val sp = ctx.applicationContext.getSharedPreferences("config", Context.MODE_PRIVATE)

    fun load(): Config {
        val d = Config()
        var pass = sp.getString("pass", null)
        var hpass = sp.getString("hotspotPass", null)
        if (pass == null || hpass == null) {
            pass = pass ?: randomPassword()
            hpass = hpass ?: randomPassword()
            sp.edit().putString("pass", pass).putString("hotspotPass", hpass).apply()
        }
        return Config(
            port = sp.getInt("port", d.port),
            auth = sp.getBoolean("auth", d.auth),
            user = sp.getString("user", d.user) ?: d.user,
            pass = pass,
            cellular = sp.getBoolean("cellular", d.cellular),
            hotspot = sp.getBoolean("hotspot", d.hotspot),
            hotspotName = sp.getString("hotspotName", d.hotspotName) ?: d.hotspotName,
            hotspotPass = hpass,
        )
    }

    fun save(c: Config) {
        sp.edit()
            .putInt("port", c.port).putBoolean("auth", c.auth)
            .putString("user", c.user).putString("pass", c.pass)
            .putBoolean("cellular", c.cellular).putBoolean("hotspot", c.hotspot)
            .putString("hotspotName", c.hotspotName).putString("hotspotPass", c.hotspotPass)
            .apply()
    }

    companion object {
        fun randomPassword(len: Int = 12): String {
            val alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            val r = SecureRandom()
            return buildString { repeat(len) { append(alphabet[r.nextInt(alphabet.length)]) } }
        }

        /** Wi-Fi Direct network names must be DIRECT-xy-..., max 32 bytes: our prefix leaves 22 for the suffix. */
        fun validHotspotName(s: String) = s.length in 1..22 && s.all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' }
        fun validHotspotPass(s: String) = s.length in 8..63 && s.all { it.code in 32..126 }
    }
}
