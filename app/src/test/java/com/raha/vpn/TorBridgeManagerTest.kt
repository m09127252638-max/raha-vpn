package com.raha.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class TorBridgeManagerTest {

    @Test
    fun torrcEnablesObfs4BridgeAndLocalSocksOnly() {
        val torrc = TorBridgeManager.buildTorrc(
            "obfs4 192.0.2.10:443 ${"a".repeat(40)} cert=YWJj iat-mode=0",
            "127.0.0.1:45678"
        )

        assertTrue(torrc.contains("UseBridges 1"))
        assertTrue(torrc.contains("ClientTransportPlugin obfs4 socks5 127.0.0.1:45678"))
        assertTrue(torrc.contains("Bridge obfs4 192.0.2.10:443"))
        assertTrue(torrc.contains("SocksPort 127.0.0.1:19050"))
        assertTrue(torrc.contains("SafeSocks 1"))
        assertFalse(torrc.contains("SocksPort 0\nSocksPort 0"))
    }

    @Test
    fun acceptsCompleteSocks5ConnectReplyWithIpv4Address() {
        val reply = byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0x4A, 0x38)
        assertTrue(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(reply)))
    }

    @Test
    fun acceptsCompleteSocks5ConnectReplyWithDomainAddress() {
        val reply = byteArrayOf(5, 0, 0, 3, 3, 't'.code.toByte(), 'o'.code.toByte(), 'r'.code.toByte(), 0x01, 0xBB.toByte())
        assertTrue(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(reply)))
    }

    @Test
    fun acceptsCompleteSocks5ConnectReplyWithIpv6Address() {
        val reply = byteArrayOf(5, 0, 0, 4) + ByteArray(16) + byteArrayOf(0x01, 0xBB.toByte())
        assertTrue(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(reply)))
    }

    @Test
    fun rejectsFailedOrMalformedSocks5ConnectReplies() {
        assertFalse(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(byteArrayOf(5, 5, 0, 1, 127, 0, 0, 1, 0, 80))))
        assertFalse(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(byteArrayOf(4, 0, 0, 1, 127, 0, 0, 1, 0, 80))))
        assertFalse(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(byteArrayOf(5, 0, 0, 9))))
        assertFalse(TorBridgeManager.consumeSocks5ConnectReply(ByteArrayInputStream(byteArrayOf(5, 0, 0, 1, 127, 0))))
    }
}
