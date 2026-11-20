package com.raha.vpn

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
class XrayTunConfigTest {
    private val uuid = "01234567-89ab-cdef-0123-456789abcdef"

    @Test
    fun buildsAndroidTunConfigWithProvidedDescriptorAndDnsRouting() {
        val outboundDocument = JSONObject(
            XrayConfigBuilder.build(
                "vless://$uuid@edge.example:443?security=tls&sni=edge.example"
            )
        )

        val root = JSONObject(
            XrayConfigBuilder.buildTunConfig(outboundDocument, tunFd = 42, torMode = false)
        )

        assertEquals("42", root.getJSONObject("env").getString("xray.tun.fd"))

        val inbound = root.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("tun", inbound.getString("protocol"))
        assertEquals(0, inbound.getInt("port"))
        assertEquals("hmag0", inbound.getJSONObject("settings").getString("name"))

        val outbounds = root.getJSONArray("outbounds")
        val proxy = outbounds.getJSONObject(0)
        assertEquals("proxy", proxy.getString("tag"))
        assertEquals(
            "edge.example",
            proxy.getJSONObject("settings").getJSONArray("vnext")
                .getJSONObject(0).getString("address")
        )
        assertEquals(
            "UseIP",
            proxy.getJSONObject("streamSettings").getJSONObject("sockopt")
                .getString("domainStrategy")
        )
        val dnsServers = root.getJSONObject("dns").getJSONArray("servers")
        assertEquals(4, dnsServers.length())
        assertEquals(
            "https+local://1.1.1.1/dns-query",
            dnsServers.getJSONObject(0).getString("address")
        )
        assertEquals(
            "full:edge.example",
            dnsServers.getJSONObject(0).getJSONArray("domains").getString(0)
        )
        assertTrue(dnsServers.getJSONObject(0).getBoolean("skipFallback"))
        assertEquals(
            "https+local://8.8.8.8/dns-query",
            dnsServers.getJSONObject(1).getString("address")
        )
        assertEquals("https://1.1.1.1/dns-query", dnsServers.getString(2))
        assertEquals("https://8.8.8.8/dns-query", dnsServers.getString(3))
        assertEquals("dns-out", outbounds.getJSONObject(1).getString("tag"))
        assertEquals("direct", outbounds.getJSONObject(2).getString("tag"))
        assertEquals("block", outbounds.getJSONObject(3).getString("tag"))

        val rules = root.getJSONObject("routing").getJSONArray("rules")
        assertEquals("53", rules.getJSONObject(0).getString("port"))
        assertEquals("dns-out", rules.getJSONObject(0).getString("outboundTag"))
        assertFalse(rules.toString().contains("\"network\":\"udp\""))
    }

    @Test
    fun skipsBootstrapDnsWhenProxyAddressIsAlreadyAnIpLiteral() {
        val outboundDocument = JSONObject(
            XrayConfigBuilder.build(
                "vless://$uuid@203.0.113.10:443?security=tls&sni=edge.example"
            )
        )
        val root = JSONObject(
            XrayConfigBuilder.buildTunConfig(outboundDocument, tunFd = 45, torMode = false)
        )
        val dnsServers = root.getJSONObject("dns").getJSONArray("servers")

        assertEquals(2, dnsServers.length())
        assertEquals("https://1.1.1.1/dns-query", dnsServers.getString(0))
        assertEquals("https://8.8.8.8/dns-query", dnsServers.getString(1))
    }

    @Test
    fun buildsTorTunConfigWithLocalSocksAndBlocksUdp() {
        val root = JSONObject(
            XrayConfigBuilder.buildTorTunConfig(43, "127.0.0.1:19050")
        )

        assertEquals("43", root.getJSONObject("env").getString("xray.tun.fd"))
        val proxy = root.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("socks", proxy.getString("protocol"))
        val server = proxy.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("127.0.0.1", server.getString("address"))
        assertEquals(19050, server.getInt("port"))

        val dnsServers = root.getJSONObject("dns").getJSONArray("servers")
        assertEquals(2, dnsServers.length())
        assertEquals("https://1.1.1.1/dns-query", dnsServers.getString(0))
        assertEquals("https://8.8.8.8/dns-query", dnsServers.getString(1))

        val rules = root.getJSONObject("routing").getJSONArray("rules")
        val udpBlock = (0 until rules.length())
            .map { rules.getJSONObject(it) }
            .firstOrNull { it.optString("network") == "udp" }
        requireNotNull(udpBlock)
        assertEquals("block", udpBlock.getString("outboundTag"))
    }

    @Test
    fun acceptsBracketedIpv6TorSocksAddress() {
        val root = JSONObject(
            XrayConfigBuilder.buildTorTunConfig(44, "[::1]:19050")
        )
        val server = root.getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("settings").getJSONArray("servers").getJSONObject(0)

        assertEquals("::1", server.getString("address"))
        assertEquals(19050, server.getInt("port"))
    }

    @Test
    fun rejectsInvalidTunDescriptorAndTorSocksAddress() {
        val outboundDocument = JSONObject(
            XrayConfigBuilder.build(
                "vless://$uuid@edge.example:443?security=tls&sni=edge.example"
            )
        )

        assertFails {
            XrayConfigBuilder.buildTunConfig(outboundDocument, tunFd = -1, torMode = false)
        }
        assertFails {
            XrayConfigBuilder.buildTorTunConfig(42, "127.0.0.1:not-a-port")
        }
        assertFails {
            XrayConfigBuilder.buildTorTunConfig(42, "127.0.0.1:70000")
        }
    }

    private fun assertFails(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Expected invalid TUN input to be rejected")
        } catch (_: IllegalArgumentException) {
            // Expected.
        } catch (_: IllegalStateException) {
            // Expected.
        }
    }
}
