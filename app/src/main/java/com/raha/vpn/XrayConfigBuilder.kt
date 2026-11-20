package com.raha.vpn

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets

/**
 * Converts common V2Ray/Xray share links into an Xray-core client config.
 * Configs contain credentials and must never be logged or sent to analytics.
 */
object XrayConfigBuilder {
    fun build(raw: String, socksPort: Int = 10808): String {
        require(socksPort in 1024..65535) { "پورت محلی SOCKS معتبر نیست" }
        val link = raw.trim()
        val outbound = when {
            link.startsWith("vmess://", true) -> vmess(link)
            link.startsWith("vless://", true) -> vlessOrTrojan(link, "vless")
            link.startsWith("trojan://", true) -> vlessOrTrojan(link, "trojan")
            else -> error("این نوع کانفیگ هنوز توسط موتور Xray پشتیبانی نشده است")
        }
        val inbound = JSONObject()
            .put("tag", "socks-in")
            .put("listen", "127.0.0.1")
            .put("port", socksPort)
            .put("protocol", "socks")
            .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
            .put("sniffing", JSONObject()
                .put("enabled", true)
                .put("destOverride", JSONArray().put("http").put("tls").put("quic")))
        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", JSONArray().put(inbound))
            .put("outbounds", JSONArray()
                .put(outbound)
                .put(JSONObject().put("tag", "direct").put("protocol", "freedom")))
            .put("routing", JSONObject().put("domainStrategy", "AsIs"))
            .toString()
    }

    /**
     * Wraps a validated Xray outbound in an Android TUN configuration.
     * The TUN descriptor is supplied by VpnService.establish() through Xray's
     * documented xray.tun.fd environment key.
     */
    fun buildTunConfig(outboundDocument: JSONObject, tunFd: Int, torMode: Boolean): String {
        require(tunFd >= 0) { "شناسه فایل TUN معتبر نیست" }
        val sourceOutbounds = outboundDocument.optJSONArray("outbounds")
            ?: error("خروجی موتور Xray خالی است")
        require(sourceOutbounds.length() > 0) { "هیچ سرور قابل‌استفاده‌ای در کانفیگ نیست" }

        val proxy = JSONObject(sourceOutbounds.getJSONObject(0).toString())
            .put("tag", "proxy")
        // Resolve the proxy server hostname through Xray's built-in DNS module.
        // This avoids Android/system DNS before the tunnel is established.
        val proxyStream = proxy.optJSONObject("streamSettings") ?: JSONObject().also {
            proxy.put("streamSettings", it)
        }
        val proxySockopt = proxyStream.optJSONObject("sockopt") ?: JSONObject().also {
            proxyStream.put("sockopt", it)
        }
        proxySockopt.put("domainStrategy", "UseIP")
        val outbounds = JSONArray()
            .put(proxy)
            .put(JSONObject()
                .put("tag", "dns-out")
                .put("protocol", "dns")
                .put("settings", JSONObject().put(
                    "rules",
                    JSONArray().put(JSONObject().put("action", "hijack"))
                )))
            .put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
            .put(JSONObject().put("tag", "block").put("protocol", "blackhole"))

        val tunInbound = JSONObject()
            .put("tag", "tun-in")
            .put("port", 0)
            .put("protocol", "tun")
            .put("settings", JSONObject().put("name", "hmag0").put("mtu", TUN_MTU))
            .put("sniffing", JSONObject()
                .put("enabled", true)
                .put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                .put("routeOnly", true))

        val dnsRule = JSONObject()
            .put("type", "field")
            .put("inboundTag", JSONArray().put("tun-in"))
            .put("port", "53")
            .put("network", "tcp,udp")
            .put("outboundTag", "dns-out")
        val rules = JSONArray().put(dnsRule)
        if (torMode) {
            // Tor's SOCKS transport is TCP-only. DNS is handled above through
            // Xray's DoH resolver; other UDP is explicitly blocked, never leaked.
            rules.put(JSONObject()
                .put("type", "field")
                .put("inboundTag", JSONArray().put("tun-in"))
                .put("network", "udp")
                .put("outboundTag", "block"))
        }

        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("env", JSONObject().put("xray.tun.fd", tunFd.toString()))
            .put("inbounds", JSONArray().put(tunInbound))
            .put("outbounds", outbounds)
            .put("dns", JSONObject()
                .put("servers", JSONArray()
                    .put("https+local://1.1.1.1/dns-query")
                    .put("https+local://8.8.8.8/dns-query"))
                .put("queryStrategy", "UseIP"))
            .put("routing", JSONObject()
                .put("domainStrategy", "AsIs")
                .put("rules", rules))
            .toString()
    }

    fun buildTorTunConfig(tunFd: Int, socksAddress: String): String {
        val host: String
        val port: Int
        if (socksAddress.startsWith("[")) {
            host = socksAddress.substringAfter("[").substringBefore("]")
            port = socksAddress.substringAfter("]:").toIntOrNull()
                ?: error("پورت SOCKS مربوط به Tor معتبر نیست")
        } else {
            host = socksAddress.substringBeforeLast(':')
            port = socksAddress.substringAfterLast(':').toIntOrNull()
                ?: error("پورت SOCKS مربوط به Tor معتبر نیست")
        }
        require(host.isNotBlank() && port in 1..65535) { "نشانی SOCKS مربوط به Tor معتبر نیست" }
        val outbound = JSONObject()
            .put("tag", "proxy")
            .put("protocol", "socks")
            .put("settings", JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", host).put("port", port)
            )))
        return buildTunConfig(JSONObject().put("outbounds", JSONArray().put(outbound)), tunFd, torMode = true)
    }

    fun outboundServerAddress(outboundDocument: JSONObject): String {
        val outbounds = outboundDocument.optJSONArray("outbounds")
            ?: error("خروجی موتور Xray خالی است")
        require(outbounds.length() > 0) { "هیچ خروجی سروری در کانفیگ نیست" }
        val settings = outbounds.getJSONObject(0).optJSONObject("settings")
            ?: error("تنظیمات سرور در کانفیگ وجود ندارد")
        val server = when {
            (settings.optJSONArray("vnext")?.length() ?: 0) > 0 ->
                settings.getJSONArray("vnext").getJSONObject(0)
            (settings.optJSONArray("servers")?.length() ?: 0) > 0 ->
                settings.getJSONArray("servers").getJSONObject(0)
            else -> error("نشانی سرور در کانفیگ پیدا نشد")
        }
        return server.optString("address").takeIf { it.isNotBlank() }
            ?: error("نشانی سرور در کانفیگ خالی است")
    }

    fun withResolvedServerAddress(outboundDocument: JSONObject, resolvedAddress: String): JSONObject {
        require(resolvedAddress.isNotBlank()) { "نشانی IP سرور خالی است" }
        val result = JSONObject(outboundDocument.toString())
        val outbounds = result.getJSONArray("outbounds")
        require(outbounds.length() > 0) { "هیچ خروجی سروری در کانفیگ نیست" }
        val settings = outbounds.getJSONObject(0).getJSONObject("settings")
        val server = when {
            (settings.optJSONArray("vnext")?.length() ?: 0) > 0 ->
                settings.getJSONArray("vnext").getJSONObject(0)
            (settings.optJSONArray("servers")?.length() ?: 0) > 0 ->
                settings.getJSONArray("servers").getJSONObject(0)
            else -> error("نشانی سرور در کانفیگ پیدا نشد")
        }
        server.put("address", resolvedAddress)
        return result
    }

    private fun vmess(link: String): JSONObject {
        val encoded = link.substringAfter("://").substringBefore('#')
        val decoded = try {
            String(Base64.decode(encoded, Base64.DEFAULT), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            error("اطلاعات لینک VMess قابل‌خواندن نیست")
        }
        val source = JSONObject(decoded)
        val host = source.optString("add").takeIf { it.isNotBlank() }
            ?: error("آدرس سرور VMess وجود ندارد")
        val port = source.optString("port").toIntOrNull()?.takeIf { it in 1..65535 }
            ?: error("پورت VMess معتبر نیست")
        val id = source.optString("id").takeIf { it.isNotBlank() }
            ?: error("شناسه VMess وجود ندارد")
        val user = JSONObject()
            .put("id", id)
            .put("alterId", source.optInt("aid", 0))
            .put("security", source.optString("scy").ifBlank { "auto" })
        val settings = JSONObject().put("vnext", JSONArray().put(
            JSONObject().put("address", host).put("port", port)
                .put("users", JSONArray().put(user))
        ))
        val outbound = JSONObject().put("tag", "proxy")
            .put("protocol", "vmess").put("settings", settings)
        val net = source.optString("net").ifBlank { "tcp" }.lowercase()
        val tls = source.optString("tls").lowercase()
        val sni = source.optString("sni").ifBlank { source.optString("host").ifBlank { host } }
        outbound.put("streamSettings", streamSettings(
            net = net,
            security = if (tls == "tls") "tls" else "none",
            host = source.optString("host"),
            path = source.optString("path"),
            serviceName = source.optString("path"),
            sni = sni,
            fingerprint = source.optString("fp"),
            allowInsecure = source.optString("allowInsecure") == "1"
        ))
        return outbound
    }

    private fun vlessOrTrojan(link: String, protocol: String): JSONObject {
        val uri = Uri.parse(link)
        val host = uri.host?.takeIf { it.isNotBlank() } ?: error("آدرس سرور در لینک وجود ندارد")
        val port = uri.port.takeIf { it in 1..65535 } ?: error("پورت سرور معتبر نیست")
        val query = query(uri.encodedQuery.orEmpty())
        require(query["headerType"].isNullOrBlank() || query["headerType"].equals("none", ignoreCase = true)) {
            "هدر TCP سفارشی هنوز پشتیبانی نمی‌شود"
        }
        val credential = uri.userInfo?.let { Uri.decode(it) }?.takeIf { it.isNotBlank() }
            ?: error("شناسه یا رمز سرور وجود ندارد")
        val security = query["security"].orEmpty().ifBlank {
            if (protocol == "trojan") "tls" else "none"
        }.lowercase()
        require(security in setOf("none", "tls", "reality")) { "روش امنیتی لینک پشتیبانی نمی‌شود" }
        require(security != "reality" || protocol == "vless") { "Reality فقط برای VLESS معتبر است" }
        require(!(protocol == "trojan" && security == "none")) { "Trojan بدون TLS پشتیبانی نمی‌شود" }

        val server = JSONObject().put("address", host).put("port", port)
        if (protocol == "vless") {
            require(UUID_REGEX.matches(credential)) { "شناسه UUID در لینک VLESS معتبر نیست" }
            server.put("users", JSONArray().put(JSONObject()
                .put("id", credential)
                .put("encryption", query["encryption"] ?: "none")
                .apply { query["flow"]?.takeIf { it.isNotBlank() }?.let { put("flow", it) } }))
        } else {
            server.put("password", credential)
        }
        val outbound = JSONObject().put("tag", "proxy").put("protocol", protocol)
            .put("settings", if (protocol == "vless") JSONObject().put("vnext", JSONArray().put(server))
                else JSONObject().put("servers", JSONArray().put(server)))
        outbound.put("streamSettings", streamSettings(
            net = query["type"] ?: query["network"] ?: "tcp",
            security = security,
            host = query["host"].orEmpty(),
            path = query["path"].orEmpty(),
            serviceName = query["serviceName"] ?: query["service_name"].orEmpty(),
            sni = query["sni"] ?: query["peer"] ?: host,
            fingerprint = query["fp"].orEmpty(),
            publicKey = query["pbk"] ?: query["publicKey"].orEmpty(),
            shortId = query["sid"].orEmpty(),
            spiderX = query["spx"].orEmpty(),
            alpn = query["alpn"].orEmpty(),
            allowInsecure = query["allowInsecure"] == "1" || query["insecure"] == "1"
        ))
        return outbound
    }

    private fun streamSettings(
        net: String,
        security: String,
        host: String,
        path: String,
        serviceName: String,
        sni: String,
        fingerprint: String,
        publicKey: String = "",
        shortId: String = "",
        spiderX: String = "",
        alpn: String = "",
        allowInsecure: Boolean
    ): JSONObject {
        val network = when (net.lowercase()) {
            "tcp" -> "tcp"
            "ws", "websocket" -> "ws"
            "grpc" -> "grpc"
            else -> error("نوع انتقال $net هنوز پشتیبانی نشده است")
        }
        val result = JSONObject().put("network", network).put("security", security)
        when (network) {
            "ws" -> {
                val ws = JSONObject().put("path", path.ifBlank { "/" })
                if (host.isNotBlank()) ws.put("headers", JSONObject().put("Host", host))
                result.put("wsSettings", ws)
            }
            "grpc" -> result.put("grpcSettings", JSONObject().put("serviceName", serviceName))
        }
        if (security == "tls") {
            val tls = JSONObject().put("serverName", sni)
            if (allowInsecure) tls.put("allowInsecure", true)
            if (fingerprint.isNotBlank()) tls.put("fingerprint", fingerprint)
            if (alpn.isNotBlank()) tls.put("alpn", JSONArray(alpn.split(',').map { it.trim() }))
            result.put("tlsSettings", tls)
        } else if (security == "reality") {
            require(publicKey.isNotBlank()) { "کلید عمومی Reality (pbk) در لینک نیست" }
            val reality = JSONObject()
                .put("serverName", sni)
                .put("fingerprint", fingerprint.ifBlank { "chrome" })
                .put("publicKey", publicKey)
                .put("shortId", shortId)
            if (spiderX.isNotBlank()) reality.put("spiderX", spiderX)
            result.put("realitySettings", reality)
        }
        return result
    }

    private fun query(encoded: String): Map<String, String> =
        encoded.split('&').filter { it.isNotBlank() }.associate { part ->
            Uri.decode(part.substringBefore('=')) to Uri.decode(part.substringAfter('=', ""))
        }

    private const val TUN_MTU = 1400
    private const val UUID_PATTERN = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    private val UUID_REGEX = Regex(UUID_PATTERN)
}
