package com.raha.vpn

import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject

/**
 * Converts supported share links into a minimal sing-box configuration.
 * Credentials are kept in memory only; callers must never log the returned JSON.
 *
 * First implementation deliberately supports VLESS and Trojan only. Other
 * schemes remain importable for storage but cannot be started yet.
 */
object ShareLinkParser {
    fun toSingBoxConfig(raw: String): String {
        val uri = Uri.parse(raw.trim())
        val scheme = uri.scheme?.lowercase() ?: error("لینک فاقد پروتکل است")
        require(scheme == "vless" || scheme == "trojan") {
            "فعلاً فقط لینک‌های VLESS و Trojan قابل اتصال هستند"
        }
        val host = uri.host?.takeIf { it.isNotBlank() } ?: error("آدرس سرور در لینک پیدا نشد")
        val port = uri.port.takeIf { it in 1..65535 } ?: error("پورت سرور معتبر نیست")
        val userInfo = uri.encodedAuthority?.substringBeforeLast('@')?.takeIf { it.isNotBlank() } ?: error("شناسه یا رمز سرور وجود ندارد")
        val query = parseQuery(uri.encodedQuery.orEmpty())
        val tag = "proxy"

        val outbound = JSONObject()
            .put("type", scheme)
            .put("tag", tag)
            .put("server", host)
            .put("server_port", port)

        if (scheme == "vless") {
            outbound.put("uuid", decode(userInfo))
            val flow = query["flow"].orEmpty()
            if (flow.isNotBlank()) outbound.put("flow", flow)
        } else {
            outbound.put("password", decode(userInfo))
        }

        val security = query["security"].orEmpty().lowercase()
        val tlsEnabled = when {
            security == "none" -> false
            security == "tls" || security == "reality" -> true
            scheme == "trojan" -> true
            else -> false
        }
        if (tlsEnabled) {
            val tls = JSONObject()
                .put("enabled", true)
                .put("server_name", query["sni"] ?: query["peer"] ?: host)
            if (query["alpn"].orEmpty().isNotBlank()) {
                tls.put("alpn", JSONArray(query.getValue("alpn").split(',').map { it.trim() }))
            }
            val insecure = query["allowInsecure"] == "1" || query["insecure"] == "1"
            if (insecure) tls.put("insecure", true)
            if (security == "reality") {
                val publicKey = query["pbk"] ?: query["publicKey"]
                    ?: error("کلید عمومی Reality (pbk) در لینک نیست")
                val reality = JSONObject().put("enabled", true)
                    .put("public_key", publicKey)
                query["sid"]?.takeIf { it.isNotBlank() }?.let { reality.put("short_id", it) }
                tls.put("reality", reality)
                tls.put("utls", JSONObject().put("enabled", true)
                    .put("fingerprint", query["fp"] ?: "chrome"))
            }
            outbound.put("tls", tls)
        }

        when (query["type"]?.lowercase() ?: query["network"]?.lowercase() ?: "tcp") {
            "tcp" -> Unit
            "ws", "websocket" -> {
                val headers = JSONObject()
                query["host"]?.takeIf { it.isNotBlank() }?.let { headers.put("Host", it) }
                val transport = JSONObject().put("type", "ws")
                    .put("path", query["path"] ?: "/")
                if (headers.length() > 0) transport.put("headers", headers)
                outbound.put("transport", transport)
            }
            "grpc" -> outbound.put("transport", JSONObject()
                .put("type", "grpc")
                .put("service_name", query["serviceName"] ?: query["service_name"] ?: ""))
            else -> error("نوع انتقال این لینک هنوز پشتیبانی نمی‌شود")
        }

        val tun = JSONObject()
            .put("type", "tun")
            .put("tag", "tun-in")
            .put("interface_name", "atena0")
            .put("inet4_address", JSONArray().put("172.19.0.1/30"))
            .put("mtu", 1400)
            .put("auto_route", true)
            .put("strict_route", true)
            .put("stack", "mixed")

        return JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("dns", JSONObject()
                .put("servers", JSONArray().put(JSONObject()
                    .put("tag", "dns-remote")
                    .put("address", "https://1.1.1.1/dns-query")
                    .put("detour", tag)))
                .put("final", "dns-remote"))
            .put("inbounds", JSONArray().put(tun))
            .put("outbounds", JSONArray()
                .put(outbound)
                .put(JSONObject().put("type", "direct").put("tag", "direct"))
                .put(JSONObject().put("type", "block").put("tag", "block")))
            .put("route", JSONObject()
                .put("auto_detect_interface", true)
                .put("final", tag))
            .toString()
    }

    private fun parseQuery(encoded: String): Map<String, String> {
        if (encoded.isBlank()) return emptyMap()
        return encoded.split('&').mapNotNull { part ->
            if (part.isBlank()) return@mapNotNull null
            val key = part.substringBefore('=')
            val value = part.substringAfter('=', "")
            decode(key) to decode(value)
        }.toMap()
    }

    private fun decode(value: String): String =
        Uri.decode(value)
}
