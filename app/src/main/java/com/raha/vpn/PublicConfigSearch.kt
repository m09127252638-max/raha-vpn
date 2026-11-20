package com.raha.vpn

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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
        // Larger, actively refreshed feeds with raw URI lines (not subscription indexes).
        "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
        "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
        // Base64 feed; decoded before scheme validation.
        "https://raw.githubusercontent.com/3000S-HTTP/sNSub/main/output/best59_base64.txt",
        // CDN mirrors help when raw.githubusercontent.com is unreachable.
        "https://cdn.jsdelivr.net/gh/morpheusadam/v2ray-config@main/subs/bundles/iran.txt",
        "https://cdn.jsdelivr.net/gh/Alirewa/V2ray-Configs@main/config.txt",
        "https://cdn.jsdelivr.net/gh/center2055/OnionHop-Bridges-Collector@main/bridge/obfs4_tested.txt",
        "https://cdn.jsdelivr.net/gh/center2055/OnionHop-Bridges-Collector@main/bridge/obfs4_72h.txt",
        "https://cdn.jsdelivr.net/gh/3000S-HTTP/sNSub@main/output/best59_base64.txt"
    )

    /**
     * Fetch feeds concurrently so one slow or blocked source does not delay every
     * other source. Return partial results if the overall 40-second budget expires.
     */
    fun fetch(): List<String> {
        val executor = Executors.newFixedThreadPool(8)
        return try {
            val tasks = sources.map { source -> Callable { fetchSource(source) } }
            executor.invokeAll(tasks, 40, TimeUnit.SECONDS)
                .map { future -> runCatching { future.get() }.getOrDefault(emptyList()) }
                .let(::prioritizeResults)
        } finally {
            executor.shutdownNow()
        }
    }


    /**
     * Parse both URI-per-line feeds and Base64 subscription bodies. Comment lines
     * are removed before format detection, so a URL in a comment cannot prevent
     * decoding a Base64 payload. This validates importability, not reachability.
     */
    internal fun parseFeedPayload(payload: String, bridgeFeed: Boolean = false): List<String> {
        val cleaned = payload.removePrefix("\\uFEFF")
            .lineSequence()
            .map(String::trim)
            .filter { line ->
                line.isNotEmpty() &&
                    !line.startsWith("#") &&
                    !line.startsWith(";") &&
                    !line.startsWith("//")
            }
            .toList()
            .joinToString("\\n")

        val decoded = if (bridgeFeed || containsSupportedUri(cleaned)) {
            cleaned
        } else {
            decodeBase64Subscription(cleaned) ?: cleaned
        }

        val allowedSchemes = setOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")
        return decoded.lineSequence()
            .map(String::trim)
            .filter { line ->
                if (bridgeFeed) {
                    line.startsWith("obfs4 ", ignoreCase = true) &&
                        ConfigStore.isSupported(line)
                } else {
                    line.substringBefore("://").lowercase() in allowedSchemes &&
                        ConfigStore.isSupported(line)
                }
            }
            .distinct()
            .take(500)
            .toList()
    }

    private fun containsSupportedUri(value: String): Boolean =
        value.lineSequence().any { line ->
            line.substringBefore("://").lowercase() in
                setOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic") &&
                line.contains("://")
        }

    private fun decodeBase64Subscription(value: String): String? {
        val compact = value.filterNot(Char::isWhitespace)
        if (compact.length < 16 || !compact.matches(Regex("[A-Za-z0-9_+/=-]+"))) return null
        val decoded = runCatching {
            String(
                Base64.decode(compact, Base64.DEFAULT or Base64.URL_SAFE),
                Charsets.UTF_8
            )
        }.getOrNull() ?: return null
        // Reject arbitrary binary or unrelated text; only accept a decoded body
        // containing at least one supported share URI.
        return decoded.takeIf(::containsSupportedUri)
    }

    internal fun prioritizeResults(resultsBySource: List<List<String>>): List<String> {
        val all = resultsBySource.flatten().distinct()
        // Bridge feeds occur after large proxy feeds. Put a small bridge sample first
        // so it is actually visible in the app's first screen of search results.
        val bridges = all.filter { it.startsWith("obfs4 ", ignoreCase = true) }.take(8)
        val proxies = all.filterNot { it.startsWith("obfs4 ", ignoreCase = true) }
        return (bridges + proxies).distinct().take(2_000)
    }

    private fun fetchSource(source: String): List<String> {
        val connection = (URL(source).openConnection() as HttpURLConnection).apply {
            connectTimeout = 8000
            readTimeout = 10000
            requestMethod = "GET"
            setRequestProperty("User-Agent", "H-MAGHSODI-Android")
        }
        try {
            if (connection.responseCode !in 200..299) return emptyList()
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
            return parseFeedPayload(raw, source.contains("obfs4_", ignoreCase = true))
        } finally {
            connection.disconnect()
        }
    }
}
