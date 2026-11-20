package com.raha.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShareLinkParserTest {
    private val uuid = "01234567-89ab-cdef-0123-456789abcdef"

    @Test
    fun acceptsValidObfs4BridgeAndRejectsMalformedBridge() {
        val valid = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=YWJjZGVmZ2hpamts iat-mode=0"
        assertTrue(ConfigStore.isSupported(valid))
        val ipv6 = "obfs4 [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=YWJjZGVmZ2hpamts iat-mode=0"
        assertTrue(ConfigStore.isSupported(ipv6))
        assertFalse(ConfigStore.isSupported("obfs4 192.0.2.10:443 invalid-fingerprint cert=bad iat-mode=0"))
        assertFalse(ConfigStore.isSupported("obfs4 192.0.2.10:99999 0123456789ABCDEF0123456789ABCDEF01234567 cert=YWJjZGVmZ2hpamts iat-mode=0"))
    }

    @Test
    fun buildsTorConfigForObfs4Bridge() {
        val bridge = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=YWJjZGVmZ2hpamts iat-mode=0"
        val torrc = TorBridgeManager.buildTorrc(bridge, "127.0.0.1:12345")
        assertTrue(torrc.contains("UseBridges 1\n"))
        assertTrue(torrc.contains("ClientTransportPlugin obfs4 socks5 127.0.0.1:12345\n"))
        assertTrue(torrc.contains("Bridge $bridge\n"))
        assertTrue(torrc.contains("SocksPort 0\n"))
        assertTrue(torrc.contains("SocksPort 127.0.0.1:19050\n"))
        assertTrue(torrc.endsWith("SafeSocks 1\n"))
    }

    @Test
    fun convertsVlessTlsWebSocketLink() {
        val raw = "vless://$uuid@edge.example:443?security=tls&type=ws&sni=cdn.example&host=cdn.example&path=%2Fgateway#test"
        val config = JSONObject(ShareLinkParser.toSingBoxConfig(raw))
        val outbound = config.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("vless", outbound.getString("type"))
        assertEquals(uuid, outbound.getString("uuid"))
        assertEquals("edge.example", outbound.getString("server"))
        assertEquals(443, outbound.getInt("server_port"))
        assertEquals("cdn.example", outbound.getJSONObject("tls").getString("server_name"))
        assertEquals("ws", outbound.getJSONObject("transport").getString("type"))
        assertEquals("/gateway", outbound.getJSONObject("transport").getString("path"))
        assertEquals("hmag0", config.getJSONArray("inbounds").getJSONObject(0).getString("interface_name"))
    }

    @Test
    fun convertsTrojanToTlsOutbound() {
        val config = JSONObject(ShareLinkParser.toSingBoxConfig(
            "trojan://secret-pass@edge.example:443?security=tls&sni=edge.example"
        ))
        val outbound = config.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("trojan", outbound.getString("type"))
        assertEquals("secret-pass", outbound.getString("password"))
        assertTrue(outbound.getJSONObject("tls").getBoolean("enabled"))
    }

    @Test
    fun rejectsTrojanWithoutTls() {
        assertThrows(IllegalArgumentException::class.java) {
            ShareLinkParser.toSingBoxConfig("trojan://secret@edge.example:443?security=none")
        }
    }

    @Test
    fun rejectsUnsupportedTransport() {
        assertThrows(IllegalStateException::class.java) {
            ShareLinkParser.toSingBoxConfig("vless://$uuid@edge.example:443?security=tls&type=kcp")
        }
    }
}
