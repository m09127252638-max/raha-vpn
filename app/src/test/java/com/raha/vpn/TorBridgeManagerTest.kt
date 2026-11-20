package com.raha.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RuntimeEnvironment
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class TorBridgeManagerTest {
    @Test
    fun torSocksAllowsThePinnedIpBasedEncryptedDnsResolver() {
        val manager = TorBridgeManager(RuntimeEnvironment.getApplication())
        val torrc = manager.buildTorrc(
            "obfs4 192.0.2.1:443 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa cert=YWJjZA== iat-mode=0",
            "127.0.0.1:12345"
        )

        assertTrue(torrc.contains("ClientTransportPlugin obfs4 socks5 127.0.0.1:12345"))
        assertTrue(torrc.contains("SocksPort 127.0.0.1:19050"))
        assertFalse(torrc.contains("SafeSocks 1"))
    }
}
