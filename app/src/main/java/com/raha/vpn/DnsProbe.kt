package com.raha.vpn

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors

data class DnsResult(
    val provider: String,
    val endpoint: String,
    val reachable: Boolean,
    val detail: String
)

/**
 * Tests public DNS-over-HTTPS resolvers using an RFC 8484 wire-format query.
 * A successful TLS/HTTP handshake alone is not counted as a working resolver:
 * the DNS response ID, RCODE and answer count are checked as well.
 */
object DnsProbe {
    private data class Provider(val name: String, val url: String)

    private val providers = listOf(
        Provider("Cloudflare", "https://cloudflare-dns.com/dns-query"),
        Provider("Google", "https://dns.google/dns-query"),
        Provider("Quad9 (امنیتی)", "https://dns.quad9.net/dns-query"),
        Provider("Quad9 (بدون فیلتر امنیتی)", "https://dns10.quad9.net/dns-query"),
        Provider("AdGuard DNS", "https://dns.adguard-dns.com/dns-query"),
        Provider("AdGuard (بدون فیلتر)", "https://unfiltered.adguard-dns.com/dns-query"),
        Provider("Mullvad DNS", "https://dns.mullvad.net/dns-query"),
        Provider("Hurricane Electric", "https://ordns.he.net/dns-query"),
        Provider("Control D (بدون فیلتر)", "https://freedns.controld.com/p0")
    )

    fun checkAll(): List<DnsResult> {
        val executor = Executors.newFixedThreadPool(4)
        return try {
            val tasks = providers.map { provider ->
                executor.submit(Callable { check(provider) })
            }
            tasks.map { task ->
                runCatching { task.get() }.getOrElse {
                    DnsResult("DNS", "", false, "بررسی این سرویس ناموفق بود")
                }
            }
        } finally {
            executor.shutdownNow()
        }
    }

    private fun check(provider: Provider): DnsResult {
        var connection: HttpURLConnection? = null
        return try {
            val query = buildQuery()
            connection = (URL(provider.url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 6_000
                readTimeout = 8_000
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/dns-message")
                setRequestProperty("Accept", "application/dns-message")
                setFixedLengthStreamingMode(query.size)
            }
            connection.outputStream.use { it.write(query) }

            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                return DnsResult(
                    provider.name, provider.url, false,
                    "پاسخ HTTP ناموفق: $code"
                )
            }

            val response = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(2048)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_DNS_RESPONSE_BYTES) error("DNS response too large")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }

            val validation = validateResponse(response, queryId = QUERY_ID)
            DnsResult(
                provider.name,
                provider.url,
                validation.first,
                validation.second
            )
        } catch (_: Exception) {
            DnsResult(
                provider.name,
                provider.url,
                false,
                "پاسخ DNS دریافت نشد یا دسترسی به سرویس مسدود است"
            )
        } finally {
            connection?.disconnect()
        }
    }

    private fun buildQuery(): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { dns ->
            dns.writeShort(QUERY_ID)
            dns.writeShort(0x0100) // Standard query, recursion desired.
            dns.writeShort(1) // QDCOUNT
            dns.writeShort(0) // ANCOUNT
            dns.writeShort(0) // NSCOUNT
            dns.writeShort(0) // ARCOUNT
            "example.com".split('.').forEach { label ->
                val bytes = label.toByteArray(Charsets.US_ASCII)
                dns.writeByte(bytes.size)
                dns.write(bytes)
            }
            dns.writeByte(0)
            dns.writeShort(TYPE_A)
            dns.writeShort(CLASS_IN)
        }
        return output.toByteArray()
    }

    private fun validateResponse(response: ByteArray, queryId: Int): Pair<Boolean, String> {
        if (response.size < DNS_HEADER_BYTES) {
            return false to "پاسخ DNS ناقص بود"
        }
        val id = unsignedShort(response, 0)
        if (id != queryId) return false to "شناسه پاسخ DNS معتبر نبود"

        val flags = unsignedShort(response, 2)
        if ((flags and 0x8000) == 0) return false to "پیام دریافتی پاسخ DNS نبود"

        val rcode = flags and 0x000F
        if (rcode != 0) return false to "خطای DNS با کد $rcode"

        val answerCount = unsignedShort(response, 6)
        if (answerCount < 1) return false to "پاسخ DNS رکوردی برای دامنه آزمایشی نداشت"

        return true to "پاسخ واقعی DNS دریافت شد"
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or
            (bytes[offset + 1].toInt() and 0xFF)

    private const val QUERY_ID = 0x484D
    private const val TYPE_A = 1
    private const val CLASS_IN = 1
    private const val DNS_HEADER_BYTES = 12
    private const val MAX_DNS_RESPONSE_BYTES = 65_536
}
