package com.raha.vpn

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors

/**
 * Public discovery catalog. These are third-party feeds, not trusted server
 * operators. Every returned item is syntax-filtered and de-duplicated; a
 * syntactically valid endpoint is NOT proof that it is online or safe.
 */
object PublicConfigSearch {
    private enum class Kind { XRAY_SHARE_LINKS, OBFS4_BRIDGES }
    private data class Source(val url: String, val kind: Kind)

    // Keep multiple independent maintainers and mirrors. The app currently
    // connects only VMess, VLESS and Trojan through Xray, plus obfs4 through Tor.
    private val sources = listOf(
        Source("https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://cdn.jsdelivr.net/gh/morpheusadam/v2ray-config@main/subs/bundles/lite.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/light.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/vless.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", Kind.XRAY_SHARE_LINKS),
        Source("https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt", Kind.XRAY_SHARE_LINKS),

        Source("https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4_tested.txt", Kind.OBFS4_BRIDGES),
        Source("https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4_72h.txt", Kind.OBFS4_BRIDGES),
        Source("https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_tested.txt", Kind.OBFS4_BRIDGES),
        Source("https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4_72h.txt", Kind.OBFS4_BRIDGES)
    )

    /**
     * Fetches independent sources concurrently with a small bounded pool.
     * A failed or oversized feed is skipped without cancelling other feeds.
     */
    fun fetch(): List<String> {
        val executor = Executors.newFixedThreadPool(4)
        return try {
            val tasks = sources.map { source ->
                executor.submit(Callable { fetchSource(source) })
            }
            val unique = linkedSetOf<String>()
            tasks.forEach { task ->
                runCatching { task.get() }.getOrDefault(emptyList()).forEach { item ->
                    if (unique.size < MAX_TOTAL_RESULTS) unique.add(item)
                }
            }
            unique.toList()
        } finally {
            executor.shutdownNow()
        }
    }

    private fun fetchSource(source: Source): List<String> {
        val connection = (URL(source.url).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            requestMethod = "GET"
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "H-MAGHSODI-Android")
            setRequestProperty("Accept", "text/plain,*/*")
        }

        return try {
            if (connection.responseCode !in 200..299) return emptyList()
            val bytes = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_SOURCE_BYTES) return emptyList()
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            val raw = bytes.toString(Charsets.UTF_8).removePrefix("\uFEFF")
            val payload = when (source.kind) {
                Kind.OBFS4_BRIDGES -> raw
                Kind.XRAY_SHARE_LINKS -> decodeSubscriptionIfNeeded(raw)
            }

            payload.lineSequence()
                .map { it.trim().removePrefix("\uFEFF") }
                .filter { line -> isUsableCandidate(line, source.kind) }
                .distinct()
                .take(MAX_PER_SOURCE_RESULTS)
                .toList()
        } catch (_: Exception) {
            emptyList()
        } finally {
            connection.disconnect()
        }
    }

    private fun decodeSubscriptionIfNeeded(raw: String): String {
        val lines = raw.lineSequence().map { it.trim() }
        val hasDirectLinks = lines.any { line ->
            line.startsWith("vless://", true) ||
                line.startsWith("vmess://", true) ||
                line.startsWith("trojan://", true)
        }
        if (hasDirectLinks) return raw

        val compact = raw.filterNot { it.isWhitespace() }
        if (compact.isBlank()) return ""
        val decoded = runCatching {
            Base64.decode(compact, Base64.DEFAULT)
        }.recoverCatching {
            Base64.decode(compact, Base64.URL_SAFE or Base64.NO_WRAP)
        }.getOrNull() ?: return ""
        return String(decoded, Charsets.UTF_8)
            .takeIf { text -> !text.trimStart().startsWith("<!doctype", true) && !text.trimStart().startsWith("<html", true) }
            .orEmpty()
    }

    private fun isUsableCandidate(line: String, kind: Kind): Boolean {
        if (line.isBlank() || line.startsWith("#") || line.startsWith("//")) return false
        return when (kind) {
            Kind.OBFS4_BRIDGES ->
                line.startsWith("obfs4 ", ignoreCase = true) &&
                    ConfigStore.isSupported(line)
            Kind.XRAY_SHARE_LINKS -> {
                val scheme = line.substringBefore("://", "").lowercase()
                scheme in SUPPORTED_XRAY_SCHEMES && ConfigStore.isSupported(line)
            }
        }
    }

    private const val CONNECT_TIMEOUT_MS = 6_000
    private const val READ_TIMEOUT_MS = 10_000
    private const val MAX_SOURCE_BYTES = 1_500_000
    private const val MAX_PER_SOURCE_RESULTS = 350
    private const val MAX_TOTAL_RESULTS = 1_500
    private val SUPPORTED_XRAY_SCHEMES = setOf("vless", "trojan")
}
