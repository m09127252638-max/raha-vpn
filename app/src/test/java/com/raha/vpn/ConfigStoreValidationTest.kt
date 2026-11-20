package com.raha.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigStoreValidationTest {
    private val validObfs4 =
        "obfs4 192.0.2.10:443 " + "a".repeat(40) + " cert=AQID iat-mode=0"

    @Test
    fun acceptsSupportedProxySchemes() {
        listOf(
            "vless://id@example.com:443",
            "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSJ9",
            "trojan://password@example.com:443",
            "hysteria2://password@example.com:443"
        ).forEach { assertTrue("Expected supported scheme: $it", ConfigStore.isSupported(it)) }

        val key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val wireGuardConfig = """
            [Interface]
            PrivateKey = $key
            Address = 10.66.0.2/32

            [Peer]
            PublicKey = $key
            Endpoint = wg.example.net:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        assertTrue("Expected standard WireGuard config to be supported", ConfigStore.isSupported(wireGuardConfig))
        assertFalse("Custom WireGuard share URIs are not supported", ConfigStore.isSupported("wireguard://private-key@example.com:51820"))
    }

    @Test
    fun rejectsUnknownAndMalformedSchemes() {
        assertFalse(ConfigStore.isSupported("ftp://example.com/file"))
        assertFalse(ConfigStore.isSupported("not-a-config"))
        assertFalse("Oversized configurations must be rejected", ConfigStore.isSupported("vless://" + "a".repeat(128 * 1024)))
        assertFalse(ConfigStore.isSupported("obfs4 not-a-valid-bridge"))
        assertFalse("Hysteria v1 is not implemented", ConfigStore.isSupported("hysteria://password@example.com:443"))
        assertFalse("AnyTLS is not implemented", ConfigStore.isSupported("anytls://password@example.com:443"))
        assertFalse("Standalone SOCKS links are not implemented", ConfigStore.isSupported("socks5://user:pass@example.com:1080"))
    }

    @Test
    fun acceptsValidObfs4BridgeAndBridgePrefix() {
        assertTrue(ConfigStore.isSupported(validObfs4))
        assertTrue(ConfigStore.isSupported("Bridge $validObfs4"))
        assertTrue(ConfigStore.isSupported("BRIDGE $validObfs4"))
        assertTrue(ConfigStore.isSupported("bridge $validObfs4"))
        assertTrue(ConfigStore.isSupported(validObfs4.replaceFirst("obfs4", "OBFS4")))
        assertTrue(ConfigStore.isSupported("Bridge " + validObfs4.replaceFirst("obfs4", "OBFS4")))
    }

    @Test
    fun canonicalizesBridgeAndObfs4KeywordsForTor() {
        val canonical = validObfs4
        assertTrue(ConfigStore.normalizeObfs4Bridge(canonical) == canonical)
        assertTrue(ConfigStore.normalizeObfs4Bridge("BRIDGE OBFS4 " + canonical.substringAfter("obfs4 ")) == canonical)
        assertTrue(ConfigStore.normalizeObfs4Bridge("Bridge " + canonical.replaceFirst("obfs4", "ObFs4")) == canonical)
    }

    @Test
    fun rejectsObfs4InvalidPortsAndFingerprints() {
        val invalidPort = validObfs4.replace(":443 ", ":70000 ")
        val shortFingerprint = validObfs4.replace("a".repeat(40), "a".repeat(39))
        assertFalse(ConfigStore.isSupported(invalidPort))
        assertFalse(ConfigStore.isSupported(shortFingerprint))
    }
}
