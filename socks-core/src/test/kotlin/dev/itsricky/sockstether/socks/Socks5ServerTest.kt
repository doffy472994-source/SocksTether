package dev.itsricky.sockstether.socks

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Socks5ServerTest {
    private val servers = mutableListOf<Socks5Server>()
    private val loopback = InetAddress.getByName("127.0.0.1")

    @AfterTest fun cleanup() { servers.forEach { it.stop() } }

    private fun server(creds: Credentials? = null, allowed: (InetAddress) -> Boolean = { true }) =
        Socks5Server(0, DefaultOutbound(), creds, allowed).also { it.start(); servers += it }

    private fun echoTcp(): ServerSocket {
        val s = ServerSocket(0)
        thread(isDaemon = true) {
            while (true) {
                val c = try { s.accept() } catch (e: Exception) { break }
                thread(isDaemon = true) { c.use { c.getInputStream().copyTo(c.getOutputStream()) } }
            }
        }
        return s
    }

    private fun connectReq(atyp: Int, addr: ByteArray, port: Int): ByteArray {
        val head = byteArrayOf(5, 1, 0, atyp.toByte())
        return head + addr + byteArrayOf((port shr 8).toByte(), port.toByte())
    }

    private fun domain(name: String) = byteArrayOf(name.length.toByte()) + name.toByteArray()

    /** Reads a full SOCKS5 reply and returns its REP code. */
    private fun readReply(inp: DataInputStream): Int {
        val h = ByteArray(4).also { inp.readFully(it) }
        val skip = if (h[3].toInt() == 4) 18 else 6
        inp.readFully(ByteArray(skip))
        return h[1].toInt()
    }

    @Test fun connectNoAuthEchoesData() {
        val echo = echoTcp()
        val srv = server()
        Socket(loopback, srv.boundPort).use { s ->
            val out = s.getOutputStream(); val inp = DataInputStream(s.getInputStream())
            out.write(byteArrayOf(5, 1, 0))
            assertEquals(listOf<Byte>(5, 0), ByteArray(2).also { inp.readFully(it) }.toList())
            out.write(connectReq(1, loopback.address, echo.localPort))
            assertEquals(0, readReply(inp))
            out.write("hello socks".toByteArray())
            assertEquals("hello socks", String(ByteArray(11).also { inp.readFully(it) }))
        }
        val deadline = System.currentTimeMillis() + 2000
        while ((srv.bytesUp.get() < 11 || srv.bytesDown.get() < 11) && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertTrue(srv.bytesUp.get() >= 11 && srv.bytesDown.get() >= 11)
    }

    @Test fun connectByDomainName() {
        val echo = echoTcp()
        val srv = server()
        Socket(loopback, srv.boundPort).use { s ->
            val out = s.getOutputStream(); val inp = DataInputStream(s.getInputStream())
            out.write(byteArrayOf(5, 1, 0)); inp.readFully(ByteArray(2))
            out.write(connectReq(3, domain("localhost"), echo.localPort))
            assertEquals(0, readReply(inp))
            out.write("x".toByteArray())
            assertEquals('x'.code, inp.read())
        }
    }

    private fun authExchange(s: Socket, user: String, pass: String): Int {
        val out = s.getOutputStream(); val inp = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 2))
        assertEquals(listOf<Byte>(5, 2), ByteArray(2).also { inp.readFully(it) }.toList())
        out.write(byteArrayOf(1, user.length.toByte()) + user.toByteArray() + byteArrayOf(pass.length.toByte()) + pass.toByteArray())
        return ByteArray(2).also { inp.readFully(it) }[1].toInt()
    }

    @Test fun userPassAuthAcceptsCorrectAndRejectsWrong() {
        val echo = echoTcp()
        val srv = server(Credentials("ricky", "s3cret"))
        Socket(loopback, srv.boundPort).use { s ->
            assertEquals(0, authExchange(s, "ricky", "s3cret"))
            s.getOutputStream().write(connectReq(1, loopback.address, echo.localPort))
            assertEquals(0, readReply(DataInputStream(s.getInputStream())))
        }
        Socket(loopback, srv.boundPort).use { s -> assertEquals(1, authExchange(s, "ricky", "nope")) }
    }

    @Test fun authRequiredRejectsNoAuthMethod() {
        val srv = server(Credentials("a", "b"))
        Socket(loopback, srv.boundPort).use { s ->
            s.getOutputStream().write(byteArrayOf(5, 1, 0))
            val r = ByteArray(2).also { DataInputStream(s.getInputStream()).readFully(it) }
            assertEquals(0xFF.toByte(), r[1])
        }
    }

    @Test fun refusedConnectionReturnsRep5() {
        val dead = ServerSocket(0).use { it.localPort }
        val srv = server()
        Socket(loopback, srv.boundPort).use { s ->
            val out = s.getOutputStream(); val inp = DataInputStream(s.getInputStream())
            out.write(byteArrayOf(5, 1, 0)); inp.readFully(ByteArray(2))
            out.write(connectReq(1, loopback.address, dead))
            assertEquals(5, readReply(inp))
        }
    }

    @Test fun disallowedClientIsDropped() {
        val srv = server(allowed = { false })
        Socket(loopback, srv.boundPort).use { s ->
            s.soTimeout = 3000
            s.getOutputStream().write(byteArrayOf(5, 1, 0))
            assertEquals(-1, s.getInputStream().read())
        }
    }

    @Test fun udpAssociateRelaysBothWays() {
        val echo = DatagramSocket(0, loopback)
        thread(isDaemon = true) {
            val b = ByteArray(2048); val p = DatagramPacket(b, b.size)
            while (true) {
                try { echo.receive(p) } catch (e: Exception) { break }
                echo.send(DatagramPacket(b, p.length, p.address, p.port)); p.length = b.size
            }
        }
        val srv = server()
        Socket(loopback, srv.boundPort).use { ctl ->
            val out = ctl.getOutputStream(); val inp = DataInputStream(ctl.getInputStream())
            out.write(byteArrayOf(5, 1, 0)); inp.readFully(ByteArray(2))
            out.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
            val h = ByteArray(4).also { inp.readFully(it) }
            assertEquals(0, h[1].toInt())
            inp.readFully(ByteArray(4))
            val relayPort = inp.readUnsignedShort()

            DatagramSocket(0, loopback).use { u ->
                u.soTimeout = 3000
                val hdr = byteArrayOf(0, 0, 0, 1) + loopback.address +
                    byteArrayOf((echo.localPort shr 8).toByte(), echo.localPort.toByte())
                val msg = hdr + "ping".toByteArray()
                u.send(DatagramPacket(msg, msg.size, loopback, relayPort))
                val rb = ByteArray(2048); val rp = DatagramPacket(rb, rb.size)
                u.receive(rp)
                assertEquals("ping", String(rb, 10, rp.length - 10))
                assertEquals(1, rb[3].toInt())
            }
        }
        echo.close()
    }
}
