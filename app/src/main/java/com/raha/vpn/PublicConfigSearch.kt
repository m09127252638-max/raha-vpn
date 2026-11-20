package com.raha.vpn

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URL

object PublicConfigSearch {
    private val sources = listOf(
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
        "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
        "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_tested.txt",
        "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_72h.txt",
        // Independently maintained, frequently refreshed public feeds.
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
        "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt"
    )

    fun fetch(): List<String> {
        val found = linkedSetOf<String>()
        sources.forEach { source ->
            runCatching {
                val connection = (URL(source).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 8000
                    readTimeout = 10000
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "H-MAGHSODI-Android")
                }
                try {
                    if (connection.responseCode !in 200..299) return@runCatching
                    val bytes = connection.inputStream.use { input ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        var total = 0
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total > 1_500_000) error("Subscription too large")
                            output.write(buffer, 0, count)
                        }
                        output.toByteArray()
                    }
                    val raw = bytes.toString(Charsets.UTF_8)
                    val decoded = if (source.contains("obfs4_", ignoreCase = true) || raw.contains("://")) raw else runCatching {
                        String(Base64.decode(raw.filterNot { it.isWhitespace() }, Base64.DEFAULT), Charsets.UTF_8)
                    }.getOrDefault("")
                    decoded.lineSequence().map { it.trim() }
                        .filter { line ->
                            if (source.contains("obfs4_", ignoreCase = true)) {
                                line.startsWith("obfs4 ", ignoreCase = true) &&
                                    ConfigStore.isSupported(line)
                            } else {
                                line.substringBefore("://").lowercase() in setOf("vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "wg", "anytls") &&
                                    ConfigStore.isSupported(line)
                            }
                        }
                        .take(500).forEach { found.add(it) }
                } finally { connection.disconnect() }
            }
        }
        return found.toList()
    }
}