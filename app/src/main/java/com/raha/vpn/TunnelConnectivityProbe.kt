package com.raha.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

internal data class TunnelProbeResult(
    val success: Boolean,
    val vpnTransportDetected: Boolean,
    val latencyMs: Long?,
    val detail: String
)

/**
 * Verifies that the app can complete an HTTPS request while Android reports
 * a VPN as its active transport. This is stronger than a service-start event
 * or a standalone DNS probe, but it does not prove every app is routed.
 */
internal object TunnelConnectivityProbe {
    private const val TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
    private const val MAX_RESPONSE_BYTES = 8 * 1024

    fun check(context: Context): TunnelProbeResult {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val activeNetwork = connectivity.activeNetwork
        val capabilities = activeNetwork?.let(connectivity::getNetworkCapabilities)
        val vpnTransport = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        if (!vpnTransport) {
            return TunnelProbeResult(
                success = false,
                vpnTransportDetected = false,
                latencyMs = null,
                detail = "اندروید شبکهٔ فعال را VPN تشخیص نداد؛ اتصال واقعی تأیید نشد."
            )
        }

        val startedAt = SystemClock.elapsedRealtime()
        var connection: HttpURLConnection? = null
        return try {
            val vpnNetwork = activeNetwork ?: error("شبکهٔ VPN در دسترس نیست")
            connection = (vpnNetwork.openConnection(URL(TRACE_URL)) as HttpURLConnection).apply {
                connectTimeout = 7_000
                readTimeout = 7_000
                requestMethod = "GET"
                useCaches = false
                instanceFollowRedirects = false
                setRequestProperty("Cache-Control", "no-cache")
                setRequestProperty("User-Agent", "H-MAGHSODI-Android")
            }
            val status = connection.responseCode
            if (status !in 200..299) error("HTTP $status")
            val body = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > MAX_RESPONSE_BYTES) {
                        error("پاسخ آزمایش بیش از حد بزرگ بود")
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray().toString(Charsets.UTF_8)
            }
            val exitIp = parseTraceExitIp(body)
            if (exitIp == null) {
                TunnelProbeResult(
                    success = false,
                    vpnTransportDetected = true,
                    latencyMs = SystemClock.elapsedRealtime() - startedAt,
                    detail = "تونل VPN دیده شد، اما پاسخ HTTPS معتبر از مسیر تونل دریافت نشد."
                )
            } else {
                TunnelProbeResult(
                    success = true,
                    vpnTransportDetected = true,
                    latencyMs = SystemClock.elapsedRealtime() - startedAt,
                    detail = "عبور HTTPS از شبکهٔ VPN تأیید شد؛ IP خروجی دریافت شد."
                )
            }
        } catch (error: Exception) {
            TunnelProbeResult(
                success = false,
                vpnTransportDetected = vpnTransport,
                latencyMs = SystemClock.elapsedRealtime() - startedAt,
                detail = "آزمایش ترافیک تونل ناموفق بود: ${error.message ?: "خطای شبکه"}"
            )
        } finally {
            connection?.disconnect()
        }
    }

    internal fun parseTraceExitIp(body: String): String? {
        val value = body.lineSequence()
            .firstOrNull { it.startsWith("ip=") }
            ?.substringAfter("ip=")
            ?.trim()
            ?: return null
        if (value.length !in 3..45) return null
        return value.takeIf {
            it.matches(Regex("[0-9a-fA-F:.]+")) && it.any(Char::isDigit)
        }
    }
}
