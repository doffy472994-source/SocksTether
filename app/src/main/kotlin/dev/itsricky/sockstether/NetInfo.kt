package dev.itsricky.sockstether

import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface

data class LocalAddress(val iface: String, val ip: String, val clientFacing: Boolean)

object NetInfo {
    private val cellularPrefixes = listOf("rmnet", "ccmni", "v4-rmnet", "pdp", "wwan", "clat")
    private val ignoredPrefixes = listOf("lo", "dummy", "tun")

    fun localAddresses(): List<LocalAddress> = try {
        (NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList())
            .filter { it.isUp && !it.isLoopback }
            .flatMap { ni ->
                ni.inetAddresses.toList()
                    .filterIsInstance<Inet4Address>()
                    .filter { !it.isLinkLocalAddress }
                    .map { a ->
                        val cell = cellularPrefixes.any { ni.name.startsWith(it) }
                        val ignore = ignoredPrefixes.any { ni.name.startsWith(it) }
                        LocalAddress(ni.name, a.hostAddress ?: "", !cell && !ignore)
                    }
            }
            .sortedByDescending { it.clientFacing }
    } catch (e: Exception) {
        emptyList()
    }

    /** Only LAN-side clients may use the proxy; refuses anything arriving from the public/cellular side. */
    fun isLocalClient(a: InetAddress): Boolean =
        a.isSiteLocalAddress || a.isLinkLocalAddress || a.isLoopbackAddress
}
