package dev.itsricky.sockstether.socks

import java.io.BufferedInputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Where outbound traffic leaves the device. Android binds this to the cellular network. */
interface Outbound {
    @Throws(IOException::class) fun resolve(host: String): InetAddress
    @Throws(IOException::class) fun openTcp(addr: InetAddress, port: Int, timeoutMs: Int): Socket
    @Throws(IOException::class) fun openUdp(): DatagramSocket
}

class DefaultOutbound : Outbound {
    override fun resolve(host: String): InetAddress = InetAddress.getByName(host)

    override fun openTcp(addr: InetAddress, port: Int, timeoutMs: Int): Socket {
        val s = Socket()
        try {
            s.connect(InetSocketAddress(addr, port), timeoutMs)
        } catch (e: IOException) {
            s.close(); throw e
        }
        return s
    }

    override fun openUdp(): DatagramSocket = DatagramSocket()
}

class Credentials(val user: String, val pass: String)

/**
 * Minimal SOCKS5 server (RFC 1928 + RFC 1929 user/pass).
 * Supports CONNECT and UDP ASSOCIATE; domain names are resolved through [outbound].
 */
class Socks5Server(
    private val port: Int,
    private val outbound: Outbound,
    private val credentials: Credentials? = null,
    private val clientAllowed: (InetAddress) -> Boolean = { true },
    private val log: (String) -> Unit = {},
) {
    val activeConnections = AtomicInteger()
    val bytesUp = AtomicLong()   // client -> internet
    val bytesDown = AtomicLong() // internet -> client

    @Volatile private var running = false
    private var server: ServerSocket? = null
    private val open = ConcurrentHashMap.newKeySet<Closeable>()
    private val pool = Executors.newCachedThreadPool { r -> Thread(r, "socks").apply { isDaemon = true } }

    val boundPort: Int get() = server?.localPort ?: -1

    @Throws(IOException::class)
    fun start() {
        val s = ServerSocket()
        s.reuseAddress = true
        s.bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), port), 128)
        server = s
        running = true
        thread(isDaemon = true, name = "socks-accept") {
            while (running) {
                val c = try { s.accept() } catch (e: IOException) { break }
                try { pool.execute { handle(c) } } catch (e: Exception) { c.close(); break }
            }
        }
    }

    fun stop() {
        running = false
        runCatching { server?.close() }
        open.toList().forEach { runCatching { it.close() } }
        open.clear()
        pool.shutdownNow()
    }

    // ---------------------------------------------------------------- TCP session

    private fun handle(c: Socket) {
        open.add(c)
        activeConnections.incrementAndGet()
        try {
            if (!clientAllowed(c.inetAddress)) return
            c.tcpNoDelay = true
            c.soTimeout = 15_000 // handshake timeout only
            val input = DataInputStream(BufferedInputStream(c.getInputStream()))
            val output = c.getOutputStream()
            if (!negotiate(input, output)) return

            if (input.readUnsignedByte() != 5) return
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val host = readAddress(input)
            if (host == null) { reply(output, 8); return }
            val dstPort = input.readUnsignedShort()
            c.soTimeout = 0

            when (cmd) {
                1 -> connect(c, input, output, host, dstPort)
                3 -> udpAssociate(c, input, output)
                else -> reply(output, 7)
            }
        } catch (_: IOException) {
        } finally {
            runCatching { c.close() }
            open.remove(c)
            activeConnections.decrementAndGet()
        }
    }

    private fun negotiate(input: DataInputStream, output: OutputStream): Boolean {
        if (input.readUnsignedByte() != 5) return false
        val methods = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
        val want: Byte = if (credentials == null) 0 else 2
        if (want !in methods) {
            output.write(byteArrayOf(5, 0xFF.toByte())); output.flush(); return false
        }
        output.write(byteArrayOf(5, want)); output.flush()
        if (credentials == null) return true

        if (input.readUnsignedByte() != 1) return false
        val user = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
        val pass = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
        val ok = MessageDigest.isEqual(user, credentials.user.toByteArray()) and
            MessageDigest.isEqual(pass, credentials.pass.toByteArray())
        output.write(byteArrayOf(1, if (ok) 0 else 1)); output.flush()
        if (!ok) log("Rejected bad credentials from a client")
        return ok
    }

    private fun readAddress(input: DataInputStream): String? = when (input.readUnsignedByte()) {
        1 -> InetAddress.getByAddress(ByteArray(4).also { input.readFully(it) }).hostAddress
        4 -> InetAddress.getByAddress(ByteArray(16).also { input.readFully(it) }).hostAddress
        3 -> String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) }, Charsets.ISO_8859_1)
        else -> null
    }

    private fun reply(out: OutputStream, rep: Int, addr: InetAddress? = null, port: Int = 0) {
        val a = addr?.address ?: ByteArray(4)
        val b = ByteArray(6 + a.size)
        b[0] = 5; b[1] = rep.toByte(); b[2] = 0; b[3] = if (a.size == 4) 1 else 4
        System.arraycopy(a, 0, b, 4, a.size)
        b[4 + a.size] = (port shr 8).toByte(); b[5 + a.size] = port.toByte()
        out.write(b); out.flush()
    }

    private fun connect(c: Socket, input: InputStream, output: OutputStream, host: String, dstPort: Int) {
        val remote = try {
            outbound.openTcp(outbound.resolve(host), dstPort, 10_000)
        } catch (e: UnknownHostException) { reply(output, 4); return }
        catch (e: ConnectException) { reply(output, 5); return }
        catch (e: SocketTimeoutException) { reply(output, 6); return }
        catch (e: NoRouteToHostException) { reply(output, 3); return }
        catch (e: IOException) { reply(output, 1); return }

        open.add(remote)
        try {
            remote.tcpNoDelay = true
            reply(output, 0, remote.localAddress, remote.localPort)
            log("CONNECT $host:$dstPort")
            val down = thread(isDaemon = true, name = "socks-down") {
                pump(remote.getInputStream(), c, bytesDown, remote)
            }
            pump(input, remote, bytesUp, c)
            try { down.join() } catch (_: InterruptedException) { /* server stopping */ }
        } finally {
            runCatching { remote.close() }
            open.remove(remote)
        }
    }

    private fun pump(src: InputStream, dst: Socket, counter: AtomicLong, other: Socket) {
        val buf = ByteArray(16 * 1024)
        try {
            val o = dst.getOutputStream()
            while (true) {
                val n = src.read(buf)
                if (n < 0) break
                o.write(buf, 0, n)
                counter.addAndGet(n.toLong())
            }
            runCatching { dst.shutdownOutput() } // half-close, let the other direction drain
        } catch (e: IOException) {
            runCatching { dst.close() }
            runCatching { other.close() }
        }
    }

    // ---------------------------------------------------------------- UDP ASSOCIATE

    private fun udpAssociate(c: Socket, input: InputStream, output: OutputStream) {
        val clientIp = c.inetAddress
        val relay = DatagramSocket(InetSocketAddress(c.localAddress, 0)) // client-facing
        val up = outbound.openUdp()                                       // internet-facing
        open.add(relay); open.add(up)
        try {
            reply(output, 0, c.localAddress, relay.localPort)
            log("UDP ASSOCIATE from ${clientIp.hostAddress}")
            val client = AtomicReference<SocketAddress?>()
            val dnsCache = ConcurrentHashMap<String, InetAddress>()

            thread(isDaemon = true, name = "socks-udp-up") {
                val buf = ByteArray(65535)
                val p = DatagramPacket(buf, buf.size)
                while (true) {
                    p.length = buf.size
                    try { relay.receive(p) } catch (e: IOException) { break }
                    if (p.address != clientIp) continue
                    client.set(p.socketAddress)
                    try {
                        val len = p.length
                        if (len < 10 || buf[2].toInt() != 0) continue // too short / fragmented
                        var i = 4
                        val dest: InetAddress = when (buf[3].toInt()) {
                            1 -> { i = 8; InetAddress.getByAddress(buf.copyOfRange(4, 8)) }
                            4 -> { i = 20; if (len < 22) continue; InetAddress.getByAddress(buf.copyOfRange(4, 20)) }
                            3 -> {
                                val n = buf[4].toInt() and 0xFF
                                i = 5 + n
                                if (len < i + 2) continue
                                val name = String(buf, 5, n, Charsets.ISO_8859_1)
                                dnsCache.getOrPut(name) { outbound.resolve(name) }
                            }
                            else -> continue
                        }
                        val dport = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
                        i += 2
                        up.send(DatagramPacket(buf, i, len - i, dest, dport))
                        bytesUp.addAndGet((len - i).toLong())
                    } catch (e: IOException) {
                        if (relay.isClosed || up.isClosed) break
                    } catch (e: Exception) { /* drop malformed packet */ }
                }
            }

            thread(isDaemon = true, name = "socks-udp-down") {
                val buf = ByteArray(65535)
                val p = DatagramPacket(buf, buf.size)
                while (true) {
                    p.length = buf.size
                    try { up.receive(p) } catch (e: IOException) { break }
                    val dst = client.get() ?: continue
                    val a = p.address.address
                    val out = ByteArray(6 + a.size + p.length)
                    out[3] = if (a.size == 4) 1 else 4
                    System.arraycopy(a, 0, out, 4, a.size)
                    out[4 + a.size] = (p.port shr 8).toByte(); out[5 + a.size] = p.port.toByte()
                    System.arraycopy(buf, 0, out, 6 + a.size, p.length)
                    try { relay.send(DatagramPacket(out, out.size, dst)) } catch (e: IOException) { break }
                    bytesDown.addAndGet(p.length.toLong())
                }
            }

            // The association lives as long as the TCP control connection.
            try { while (input.read() != -1) { /* ignore */ } } catch (_: IOException) {}
        } finally {
            runCatching { relay.close() }; runCatching { up.close() }
            open.remove(relay); open.remove(up)
        }
    }
}
