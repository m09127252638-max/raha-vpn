package com.raha.vpn

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream

internal data class FeedParseReport(
    val configs: List<String>,
    val totalLines: Int,
    val accepted: Int,
    val duplicates: Int,
    val unsupported: Int,
    val malformed: Int
)

object PublicConfigSearch {
    private const val MAX_FEED_BYTES = 8 * 1024 * 1024
    private const val MAX_LINE_CHARS = 64 * 1024
    private const val MAX_FEED_LINES = 20_000
    private const val MAX_CONFIGS = 500

    private val proxySchemes = setOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")
    private val sources = listOf(
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
        "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
        "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_tested.txt",
        "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_72h.txt",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
        "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
        "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
        "https://raw.githubusercontent.com/3000S-HTTP/sNSub/main/output/best59_base64.txt",
        "https://cdn.jsdelivr.net/gh/morpheusadam/v2ray-config@main/subs/bundles/iran.txt",
        "https://cdn.jsdelivr.net/gh/Alirewa/V2ray-Configs@main/config.txt",
        "https://cdn.jsdelivr.net/gh/center2055/OnionHop-Bridges-Collector@main/bridge/obfs4_tested.txt",
        "https://cdn.jsdelivr.net/gh/center2055/OnionHop-Bridges-Collector@main/bridge/obfs4_72h.txt",
        "https://cdn.jsdelivr.net/gh/3000S-HTTP/sNSub@main/output/best59_base64.txt"
    )

    /** Concurrent discovery; results are importable candidates, not live-server claims. */
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

    internal fun parseFeedPayload(payload: String, bridgeFeed: Boolean = false): List<String> =
        parseFeedPayloadWithReport(payload, bridgeFeed).configs

    /** Bounded parser for URI-per-line and Base64 feeds, with quality counters. */
    internal fun parseFeedPayloadWithReport(
        payload: String,
        bridgeFeed: Boolean = false
    ): FeedParseReport {
        require(payload.toByteArray(Charsets.UTF_8).size <= MAX_FEED_BYTES) {
            "Subscription exceeds the 8 MiB limit"
        }

        val cleanedLines = payload.removePrefix("\uFEFF")
            .lineSequence()
            .take(MAX_FEED_LINES + 1)
            .map(String::trim)
            .filter { line ->
                line.isNotEmpty() &&
                    !line.startsWith("#") &&
                    !line.startsWith(";") &&
                    !line.startsWith("//")
            }
            .toList()

        val boundedLines = cleanedLines.take(MAX_FEED_LINES)
        val oversizedCount = boundedLines.count { it.length > MAX_LINE_CHARS }
        val safeLines = boundedLines.filter { it.length <= MAX_LINE_CHARS }
        val cleaned = safeLines.joinToString("\n")

        val decoded = if (bridgeFeed || containsSupportedUri(cleaned)) {
            cleaned
        } else {
            decodeBase64Subscription(cleaned) ?: cleaned
        }

        val accepted = LinkedHashSet<String>()
        var duplicates = 0
        var unsupported = 0
        var malformed = oversizedCount
        var total = 0

        decoded.lineSequence().forEach { rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty()) return@forEach
            total++
            if (line.length > MAX_LINE_CHARS) {
                malformed++
                return@forEach
            }

            val candidate = if (bridgeFeed) ConfigStore.normalizeObfs4Bridge(line) else line
            val isBridge = candidate.startsWith("obfs4 ", ignoreCase = true)
            val supported = if (bridgeFeed) {
                isBridge && ConfigStore.isSupported(candidate)
            } else {
                candidate.substringBefore("://").lowercase() in proxySchemes &&
                    ConfigStore.isSupported(candidate)
            }

            if (!supported) {
                unsupported++
            } else if (!accepted.add(candidate)) {
                duplicates++
            }
        }

        val result = accepted.take(MAX_CONFIGS)
        if (accepted.size > MAX_CONFIGS) unsupported += accepted.size - MAX_CONFIGS
        return FeedParseReport(
            configs = result,
            totalLines = total,
            accepted = result.size,
            duplicates = duplicates,
            unsupported = unsupported,
            malformed = malformed
        )
    }

    private fun containsSupportedUri(value: String): Boolean =
        value.lineSequence().any { line ->
            line.substringBefore("://").lowercase() in proxySchemes && line.contains("://")
        }

    private fun decodeBase64Subscription(value: String): String? {
        val compact = value.filterNot(Char::isWhitespace)
        if (compact.length < 16 || !compact.matches(Regex("[A-Za-z0-9_+/=-]+"))) return null
        val decodedBytes = runCatching { Base64.decode(compact, Base64.DEFAULT) }
            .recoverCatching { Base64.decode(compact, Base64.URL_SAFE or Base64.NO_WRAP) }
            .getOrNull() ?: return null
        if (decodedBytes.size > MAX_FEED_BYTES) return null
        val decoded = String(decodedBytes, Charsets.UTF_8)
        return decoded.takeIf(::containsSupportedUri)
    }

    fun fetchSubscription(subscriptionUrl: String): List<String> =
        fetchSubscriptionReport(subscriptionUrl).configs

    fun fetchSubscriptionReport(subscriptionUrl: String): FeedParseReport {
        require(subscriptionUrl.length <= 2048) { "Subscription URL is too long" }
        val parsed = java.net.URI(subscriptionUrl.trim())
        require(parsed.scheme.equals("https", ignoreCase = true)) {
            "Only HTTPS subscription URLs are accepted"
        }
        require(!parsed.host.isNullOrBlank() && parsed.rawUserInfo == null) {
            "Invalid subscription URL"
        }
        require(!parsed.host.equals("localhost", ignoreCase = true)) {
            "Local subscription URLs are not accepted"
        }
        return parseFeedPayloadWithReport(fetchPayload(parsed.toURL().toString()))
    }

    internal fun prioritizeResults(resultsBySource: List<List<String>>): List<String> {
        val all = resultsBySource.flatten().distinct()
        val bridges = all.filter { it.startsWith("obfs4 ", ignoreCase = true) }.take(8)
        val proxies = all.filterNot { it.startsWith("obfs4 ", ignoreCase = true) }
        return (bridges + proxies).distinct().take(2_000)
    }

    private fun fetchSource(source: String): List<String> {
        val payload = runCatching { fetchPayload(source) }.getOrNull() ?: return emptyList()
        return runCatching {
            parseFeedPayload(payload, source.contains("obfs4_", ignoreCase = true))
        }.getOrDefault(emptyList())
    }

    private fun fetchPayload(source: String): String {
        val connection = (URL(source).openConnection() as HttpURLConnection).apply {
            connectTimeout = 8_000
            readTimeout = 10_000
            requestMethod = "GET"
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "H-MAGHSODI-Android")
            setRequestProperty("Accept", "text/plain, application/octet-stream;q=0.9, */*;q=0.5")
            setRequestProperty("Accept-Encoding", "gzip")
        }
        try {
            if (!connection.url.protocol.equals("https", ignoreCase = true)) {
                error("Insecure subscription redirect rejected")
            }
            if (connection.responseCode !in 200..299) {
                error("Subscription server returned HTTP " + connection.responseCode)
            }
            val declaredLength = connection.getHeaderFieldLong("Content-Length", -1L)
            if (declaredLength > MAX_FEED_BYTES) error("Subscription exceeds the 8 MiB limit")
            val input = connection.inputStream
            val decodedInput = if (connection.contentEncoding.equals("gzip", ignoreCase = true)) {
                GZIPInputStream(input)
            } else {
                input
            }
            val bytes = decodedInput.use { readLimited(it, MAX_FEED_BYTES) }
            return bytes.toString(Charsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }

    private fun readLimited(input: InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > maxBytes) error("Subscription exceeds the 8 MiB limit")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }
}
