package com.raha.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SingBoxConfigBuilderTest {
    @Test
    fun buildsVlessRealityWebsocketTunConfig() {
        val link = "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=reality&type=ws&host=cdn.example.com&path=%2Fedge&sni=www.example.com&fp=chrome&pbk=PUBLIC_KEY&sid=abcd#test"
        val config = JSONObject(SingBoxConfigBuilder.build(link))
        val outbound = config.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vless", outbound.getString("type"))
        assertEquals("example.com", outbound.getString("server"))
        assertEquals("ws", outbound.getJSONObject("transport").getString("type"))
        assertEquals("/edge", outbound.getJSONObject("transport").getString("path"))
        assertTrue(outbound.getJSONObject("tls").getJSONObject("reality").getBoolean("enabled"))
        assertEquals("proxy", config.getJSONObject("route").getString("final"))
        assertEquals("tun", config.getJSONArray("inbounds").getJSONObject(0).getString("type"))
    }

    @Test
    fun buildsTrojanTlsGrpcConfig() {
        val link = "trojan://secret-password@example.org:8443?security=tls&type=grpc&serviceName=tunnel&sni=front.example.org#test"
        val config = JSONObject(SingBoxConfigBuilder.build(link))
        val outbound = config.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("trojan", outbound.getString("type"))
        assertEquals("secret-password", outbound.getString("password"))
        assertEquals("grpc", outbound.getJSONObject("transport").getString("type"))
        assertEquals("tunnel", outbound.getJSONObject("transport").getString("service_name"))
        assertFalse(outbound.getJSONObject("tls").optBoolean("insecure", false))
    }

    @Test
    fun buildsVmessTlsConfig() {
        val payload = """{"v":"2","ps":"vmess-test","add":"vmess.example.net","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.net","path":"/ws","tls":"tls","sni":"vmess.example.net","fp":"chrome"}"""
        val encoded = android.util.Base64.encodeToString(payload.toByteArray(), android.util.Base64.NO_WRAP)
        val config = JSONObject(SingBoxConfigBuilder.build("vmess://$encoded"))
        val outbound = config.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vmess", outbound.getString("type"))
        assertEquals("vmess.example.net", outbound.getString("server"))
        assertEquals("auto", outbound.getString("security"))
        assertEquals("vmess.example.net", outbound.getJSONObject("tls").getString("server_name"))
    }
}
