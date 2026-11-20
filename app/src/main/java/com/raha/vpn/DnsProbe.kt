package com.raha.vpn

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class DnsResult(
    val provider: String,
    val endpoint: String,
    val reachable: Boolean,
    val detail: String
)

/** Tests public DNS-over-HTTPS endpoints with a real DNS query. */
object DnsProbe {
    private data class Provider(val name: String, val url: String)

    private val providers = listOf(
        Provider("Cloudflare", "https://cloudflare-dns.com/dns-query?name=example.com&type=A"),
        Provider("Google", "https://dns.google/resolve?name=example.com&type=A"),
        Provider("AdGuard", "https://dns.adguard-dns.com/resolve?name=example.com&type=A")
    )

    fun checkAll(): List<DnsResult> = providers.map { provider ->
        var connection: HttpURLConnection? = null
        try {
            connection = URL(provider.url).openConnection() as HttpURLConnection
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/dns-json")
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_OK) {
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                val status = JSONObject(body).optInt("Status", -1)
                val ok = status == 0
                DnsResult(
                    provider.name,
                    provider.url.substringBefore("?"),
                    ok,
                    if (ok) "پاسخ DNS دریافت شد" else "پاسخ DNS معتبر نبود (کد $status)"
                )
            } else {
                DnsResult(provider.name, provider.url.substringBefore("?"), false, "خطای HTTP: $code")
            }
        } catch (_: Exception) {
            DnsResult(provider.name, provider.url.substringBefore("?"), false, "در دسترس نیست یا اتصال مسدود است")
        } finally {
            connection?.disconnect()
        }
    }
}
