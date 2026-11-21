package dev.itsricky.sockstether

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dev.itsricky.sockstether.socks.Outbound
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Sends everything the proxy forwards out over the cellular network, regardless of what the
 * system's default network is. Requesting the network also keeps mobile data up while we run.
 */
class CellularOutbound(ctx: Context) : Outbound, AutoCloseable {
    private val cm = ctx.applicationContext.getSystemService(ConnectivityManager::class.java)
    @Volatile private var network: Network? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(n: Network) { network = n; TetherState.log("Mobile data network ready") }
        override fun onLost(n: Network) { if (network == n) { network = null; TetherState.log("Mobile data network lost") } }
    }

    fun start() {
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .build()
        cm.requestNetwork(req, callback)
    }

    override fun close() {
        runCatching { cm.unregisterNetworkCallback(callback) }
        network = null
    }

    private fun net(): Network = network ?: throw IOException("No mobile data network available")

    override fun resolve(host: String): InetAddress = net().getAllByName(host).first()

    override fun openTcp(addr: InetAddress, port: Int, timeoutMs: Int): Socket {
        val n = net()
        val s = Socket()
        try {
            n.bindSocket(s)
            s.connect(InetSocketAddress(addr, port), timeoutMs)
        } catch (e: IOException) {
            s.close(); throw e
        }
        return s
    }

    override fun openUdp(): DatagramSocket {
        val s = DatagramSocket()
        try { net().bindSocket(s) } catch (e: IOException) { s.close(); throw e }
        return s
    }
}
