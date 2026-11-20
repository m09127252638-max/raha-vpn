package com.raha.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigStoreSupportTest {
    @Test
    fun acceptsOnlyShareSchemesHandledByTheXrayConnectionEngine() {
        listOf(
            "vless://id@example.com:443",
            "vmess://YWJj",
            "trojan://password@example.com:443",
            "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388",
            "socks://example.com:1080",
            "socks5://example.com:1080",
            "socks5h://example.com:1080"
        ).forEach { assertTrue("Expected supported: ${it.substringBefore("://")}", ConfigStore.isSupported(it)) }

        listOf(
            "hysteria2://password@example.com:443",
            "hy2://password@example.com:443",
            "tuic://uuid:password@example.com:443",
            "wireguard://example"
        ).forEach { assertFalse("Must not be offered as connectable: ${it.substringBefore("://")}", ConfigStore.isSupported(it)) }
    }

    @Test
    fun acceptsValidObfs4BridgeAndRejectsMalformedBridge() {
        val valid = "obfs4 192.0.2.1:443 ${"a".repeat(40)} cert=YWJjZA== iat-mode=0"
        assertTrue(ConfigStore.isSupported(valid))
        assertTrue(ConfigStore.isSupported("Bridge $valid"))
        assertFalse(ConfigStore.isSupported("obfs4 192.0.2.1:70000 ${"a".repeat(40)} cert=YWJjZA== iat-mode=0"))
        assertFalse(ConfigStore.isSupported("obfs4 not-an-endpoint fingerprint cert=YWJjZA== iat-mode=0"))
    }
}
