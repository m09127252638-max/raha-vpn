package com.raha.vpn

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class XrayConfigBuilderTest {
    private val uuid = "01234567-89ab-cdef-0123-456789abcdef"

    @Test
    fun buildsVlessRealityWebSocketConfig() {
        val raw = "vless://$uuid@edge.example:443?encryption=none&security=reality&sni=cdn.example&fp=chrome&pbk=public-key&sid=abcd&type=ws&host=cdn.example&path=%2Fgateway"
        val root = JSONObject(XrayConfigBuilder.build(raw))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")

        assertEquals("vless", outbound.getString("protocol"))
        assertEquals(uuid, outbound.getJSONObject("settings")
            .getJSONArray("vnext").getJSONObject(0)
            .getJSONArray("users").getJSONObject(0).getString("id"))
        assertEquals("reality", stream.getString("security"))
        assertEquals("public-key", stream.getJSONObject("realitySettings").getString("publicKey"))
        assertEquals("/gateway", stream.getJSONObject("wsSettings").getString("path"))
        assertEquals(10808, root.getJSONArray("inbounds").getJSONObject(0).getInt("port"))
    }

    @Test
    fun buildsTrojanTlsConfig() {
        val root = JSONObject(XrayConfigBuilder.build(
            "trojan://secret-pass@edge.example:443?security=tls&sni=edge.example&type=grpc&serviceName=tunnel"
        ))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("trojan", outbound.getString("protocol"))
        assertEquals("secret-pass", outbound.getJSONObject("settings")
            .getJSONArray("servers").getJSONObject(0).getString("password"))
        assertEquals("tunnel", outbound.getJSONObject("streamSettings")
            .getJSONObject("grpcSettings").getString("serviceName"))
    }

    @Test
    fun buildsVmessWebSocketTlsConfig() {
        val vmess = JSONObject()
            .put("add", "vmess.example")
            .put("port", "443")
            .put("id", uuid)
            .put("aid", "0")
            .put("scy", "auto")
            .put("net", "ws")
            .put("tls", "tls")
            .put("sni", "cdn.example")
            .put("host", "cdn.example")
            .put("path", "/v2")
        val encoded = Base64.encodeToString(vmess.toString().toByteArray(), Base64.NO_WRAP)
        val root = JSONObject(XrayConfigBuilder.build("vmess://$encoded"))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")

        assertEquals("vmess", outbound.getString("protocol"))
        assertEquals("vmess.example", outbound.getJSONObject("settings")
            .getJSONArray("vnext").getJSONObject(0).getString("address"))
        assertEquals("tls", stream.getString("security"))
        assertEquals("/v2", stream.getJSONObject("wsSettings").getString("path"))
    }

    @Test
    fun rejectsUnsupportedTransportAndInvalidPort() {
        try {
            XrayConfigBuilder.build("vless://$uuid@edge.example:443?type=kcp")
            throw AssertionError("KCP should not be accepted by this builder")
        } catch (_: IllegalStateException) {
            // Expected: unsupported transport must not be silently misconfigured.
        }
        try {
            XrayConfigBuilder.build("trojan://secret@edge.example:70000")
            throw AssertionError("Invalid port should not be accepted")
        } catch (_: IllegalStateException) {
            // Expected.
        }
    }

    @Test
    fun neverEnablesInsecureTlsByDefault() {
        val root = JSONObject(XrayConfigBuilder.build(
            "trojan://secret@edge.example:443?security=tls"
        ))
        val tls = root.getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertFalse(tls.optBoolean("allowInsecure", false))
        assertTrue(tls.has("serverName"))
    }
}
