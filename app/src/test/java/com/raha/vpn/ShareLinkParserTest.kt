package com.raha.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ShareLinkParserTest {
    private val uuid = "01234567-89ab-cdef-0123-456789abcdef"

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
