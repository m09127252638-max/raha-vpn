package com.raha.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ConfigStoreSupportTest {
    private val uuid = "01234567-89ab-cdef-0123-456789abcdef"

    @Test
    fun validatesConnectableProtocolsWithTheConnectionParser() {
        listOf(
            "vless://$uuid@example.com:443",
            "trojan://password@example.com:443",
            "vmess://YWJj",
            "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388",
            "socks://example.com:1080",
            "socks5://example.com:1080",
            "socks5h://example.com:1080",
            "hysteria2://password@example.com:443",
            "hy2://password@example.com:443"
        ).forEach { assertTrue("Expected supported: ${it.substringBefore("://")}", ConfigStore.isSupported(it)) }

        listOf(
            "vless://id@example.com:443",
            "vless://$uuid@example.com:70000",
            "trojan://password@example.com:443?type=kcp",
            "tuic://uuid:password@example.com:443",
            "wireguard://example"
        ).forEach { assertFalse("Must be rejected or non-connectable: ${it.substringBefore("://")}", ConfigStore.isSupported(it)) }
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
