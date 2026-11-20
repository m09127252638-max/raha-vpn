package com.raha.vpn

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * Converts supported share links into a sing-box 1.14 client configuration.
 * Credentials are kept in-memory and must never be logged.
 */
object SingBoxConfigBuilder {
    fun build(raw: String): String {
        val normalized = raw.trim()
        if (normalized.startsWith("ss://", true)) return buildShadowsocks(normalized)
        if (normalized.startsWith("hysteria2://", true) || normalized.startsWith("hy2://", true)) return buildHysteria2(normalized)
        if (normalized.startsWith("tuic://", true)) return buildTuic(normalized)
        val xray = JSONObject(XrayConfigBuilder.build(raw))
        val xrayOutbound = xray.getJSONArray("outbounds").getJSONObject(0)
        val protocol = xrayOutbound.getString("protocol")
        require(protocol in setOf("vless", "vmess", "trojan")) {
            "این پروتکل هنوز برای تونل سراسری آماده نیست"
        }

        val settings = xrayOutbound.getJSONObject("settings")
        val stream = xrayOutbound.optJSONObject("streamSettings") ?: JSONObject()
        val tlsMode = stream.optString("security", "none")
        val outbound = JSONObject()
            .put("type", protocol)
            .put("tag", "proxy")
            .put("server", serverAddress(settings, protocol))
            .put("server_port", serverPort(settings, protocol))

        when (protocol) {
            "vless" -> {
                val user = settings.getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0)
                outbound.put("uuid", user.getString("id"))
                user.optString("flow").takeIf { it.isNotBlank() }?.let { outbound.put("flow", it) }
                outbound.put("packet_encoding", "xudp")
            }
            "vmess" -> {
                val user = settings.getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0)
                outbound.put("uuid", user.getString("id"))
                outbound.put("alter_id", user.optInt("alterId", 0))
                outbound.put("security", user.optString("security", "auto"))
            }
            "trojan" -> {
                val server = settings.getJSONArray("servers").getJSONObject(0)
                outbound.put("password", server.getString("password"))
            }
        }

        if (tlsMode == "tls" || tlsMode == "reality") {
            val tls = JSONObject().put("enabled", true)
            val tlsSettings = stream.optJSONObject("tlsSettings")
            val realitySettings = stream.optJSONObject("realitySettings")
            val serverName = tlsSettings?.optString("serverName")
                ?.takeIf { !it.isNullOrBlank() }
                ?: realitySettings?.optString("serverName")
                    ?.takeIf { !it.isNullOrBlank() }
                ?: outbound.getString("server")
            tls.put("server_name", serverName)
            if (tlsSettings?.optBoolean("allowInsecure", false) == true) {
                tls.put("insecure", true)
            }
            val fingerprint = tlsSettings?.optString("fingerprint")
                ?.takeIf { it.isNotBlank() }
                ?: realitySettings?.optString("fingerprint")
            if (!fingerprint.isNullOrBlank()) {
                tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", fingerprint))
            }
            if (tlsMode == "reality") {
                val reality = realitySettings ?: error("تنظیمات Reality در لینک ناقص است")
                tls.put("reality", JSONObject()
                    .put("enabled", true)
                    .put("public_key", reality.getString("publicKey"))
                    .put("short_id", reality.optString("shortId")))
            }
            tlsSettings?.optJSONArray("alpn")?.let { tls.put("alpn", it) }
            outbound.put("tls", tls)
        }

        val network = stream.optString("network", "tcp")
        when (network) {
            "ws" -> {
                val ws = stream.optJSONObject("wsSettings") ?: JSONObject()
                val headers = ws.optJSONObject("headers") ?: JSONObject()
                val transport = JSONObject()
                    .put("type", "ws")
                    .put("path", ws.optString("path", "/"))
                headers.optString("Host").takeIf { it.isNotBlank() }?.let {
                    transport.put("headers", JSONObject().put("Host", it))
                }
                outbound.put("transport", transport)
            }
            "grpc" -> {
                val grpc = stream.optJSONObject("grpcSettings") ?: JSONObject()
                outbound.put("transport", JSONObject()
                    .put("type", "grpc")
                    .put("service_name", grpc.optString("serviceName")))
            }
            "tcp" -> Unit
            else -> error("انتقال $network برای تونل سراسری پشتیبانی نمی‌شود")
        }

        outbound.put("domain_resolver", "local-dns")
        return tunnelConfig(outbound)
    }


    private fun buildHysteria2(link: String): String {
        val uri = Uri.parse(link)
        val host = uri.host?.takeIf { it.isNotBlank() } ?: error("آدرس سرور Hysteria2 وجود ندارد")
        val port = uri.port.takeIf { it in 1..65535 } ?: error("پورت Hysteria2 معتبر نیست")
        val password = uri.userInfo?.let { Uri.decode(it) }?.takeIf { it.isNotBlank() }
            ?: error("گذرواژه Hysteria2 وجود ندارد")
        val query = queryParameters(uri)
        val tls = JSONObject().put("enabled", true)
            .put("server_name", query["sni"]?.takeIf { it.isNotBlank() } ?: host)
        query["alpn"]?.takeIf { it.isNotBlank() }?.let {
            tls.put("alpn", JSONArray(it.split(',').map(String::trim).filter(String::isNotBlank)))
        }
        query["insecure"]?.let {
            require(it == "0" || it == "1" || it.equals("true", true) || it.equals("false", true)) { "مقدار insecure در Hysteria2 معتبر نیست" }
            if (it == "1" || it.equals("true", true)) tls.put("insecure", true)
        }
        val outbound = JSONObject()
            .put("type", "hysteria2").put("tag", "proxy")
            .put("server", host).put("server_port", port)
            .put("password", password).put("tls", tls)
            .put("domain_resolver", "local-dns")
        val obfsType = query["obfs"]?.takeIf { it.isNotBlank() }
        val obfsPassword = query["obfs-password"]?.takeIf { it.isNotBlank() }
        if (obfsType != null || obfsPassword != null) {
            require(obfsType == "salamander" && obfsPassword != null) {
                "تنظیمات obfs در Hysteria2 باید salamander و دارای گذرواژه باشد"
            }
            outbound.put("obfs", JSONObject().put("type", "salamander").put("password", obfsPassword))
        }
        return tunnelConfig(outbound)
    }

    private fun buildTuic(link: String): String {
        val uri = Uri.parse(link)
        val host = uri.host?.takeIf { it.isNotBlank() } ?: error("آدرس سرور TUIC وجود ندارد")
        val port = uri.port.takeIf { it in 1..65535 } ?: error("پورت TUIC معتبر نیست")
        val credentials = uri.userInfo?.let(Uri::decode) ?: error("اطلاعات ورود TUIC وجود ندارد")
        val uuid = credentials.substringBefore(':').takeIf { it.isNotBlank() }
            ?: error("UUID در لینک TUIC وجود ندارد")
        require(Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$").matches(uuid)) {
            "UUID در لینک TUIC معتبر نیست"
        }
        val password = credentials.substringAfter(':', "").takeIf { it.isNotBlank() }
            ?: error("گذرواژه TUIC وجود ندارد")
        val query = queryParameters(uri)
        val congestion = query["congestion_control"]?.lowercase() ?: "cubic"
        require(congestion in setOf("cubic", "new_reno", "bbr")) { "الگوریتم کنترل ازدحام TUIC معتبر نیست" }
        val relayMode = query["udp_relay_mode"]?.lowercase() ?: "native"
        require(relayMode in setOf("native", "quic")) { "حالت UDP در TUIC معتبر نیست" }
        val tls = JSONObject().put("enabled", true)
            .put("server_name", query["sni"]?.takeIf { it.isNotBlank() } ?: host)
        query["alpn"]?.takeIf { it.isNotBlank() }?.let {
            tls.put("alpn", JSONArray(it.split(',').map(String::trim).filter(String::isNotBlank)))
        } ?: tls.put("alpn", JSONArray().put("h3"))
        query["allow_insecure"]?.let {
            require(it == "0" || it == "1" || it.equals("true", true) || it.equals("false", true)) { "مقدار allow_insecure در TUIC معتبر نیست" }
            if (it == "1" || it.equals("true", true)) tls.put("insecure", true)
        }
        val outbound = JSONObject()
            .put("type", "tuic").put("tag", "proxy")
            .put("server", host).put("server_port", port)
            .put("uuid", uuid).put("password", password)
            .put("congestion_control", congestion).put("udp_relay_mode", relayMode)
            .put("zero_rtt_handshake", false).put("tls", tls)
            .put("domain_resolver", "local-dns")
        query["heartbeat"]?.takeIf { it.isNotBlank() }?.let { outbound.put("heartbeat", it) }
        return tunnelConfig(outbound)
    }

    private fun queryParameters(uri: Uri): Map<String, String> =
        uri.queryParameterNames.associateWith { uri.getQueryParameter(it).orEmpty() }

    private fun buildShadowsocks(link: String): String {
        val uri = Uri.parse(link)
        require(uri.getQueryParameter("plugin").isNullOrBlank()) {
            "پلاگین جانبی Shadowsocks هنوز پشتیبانی نمی‌شود"
        }
        val encoded = link.substringAfter("ss://").substringBefore('#').substringBefore('?')
        val methodAndPassword: String
        val host: String
        val port: Int

        if (encoded.contains('@')) {
            val userInfo = encoded.substringBefore('@')
            val serverPart = encoded.substringAfter('@')
            methodAndPassword = decodeBase64(userInfo)
            val serverUri = Uri.parse("ss://$serverPart")
            host = serverUri.host?.takeIf { it.isNotBlank() } ?: error("آدرس Shadowsocks وجود ندارد")
            port = serverUri.port.takeIf { it in 1..65535 } ?: error("پورت Shadowsocks معتبر نیست")
        } else {
            val decoded = decodeBase64(encoded)
            val separator = decoded.lastIndexOf('@')
            require(separator > 0 && separator < decoded.lastIndex) {
                "ساختار لینک Shadowsocks معتبر نیست"
            }
            methodAndPassword = decoded.substring(0, separator)
            val serverUri = Uri.parse("ss://" + decoded.substring(separator + 1))
            host = serverUri.host?.takeIf { it.isNotBlank() } ?: error("آدرس Shadowsocks وجود ندارد")
            port = serverUri.port.takeIf { it in 1..65535 } ?: error("پورت Shadowsocks معتبر نیست")
        }

        val credentialSeparator = methodAndPassword.indexOf(':')
        require(credentialSeparator > 0 && credentialSeparator < methodAndPassword.lastIndex) {
            "روش رمزنگاری یا گذرواژه Shadowsocks ناقص است"
        }
        val method = methodAndPassword.substring(0, credentialSeparator)
        val password = methodAndPassword.substring(credentialSeparator + 1)
        require(method.isNotBlank() && password.isNotBlank()) {
            "روش رمزنگاری یا گذرواژه Shadowsocks خالی است"
        }

        val outbound = JSONObject()
            .put("type", "shadowsocks")
            .put("tag", "proxy")
            .put("server", host)
            .put("server_port", port)
            .put("method", method)
            .put("password", password)
            .put("domain_resolver", "local-dns")
        return tunnelConfig(outbound)
    }

    private fun decodeBase64(value: String): String {
        val normalized = value.replace('-', '+').replace('_', '/')
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        return runCatching {
            String(Base64.decode(padded, Base64.DEFAULT), Charsets.UTF_8)
        }.getOrElse {
            String(Base64.decode(padded, Base64.URL_SAFE or Base64.NO_WRAP), Charsets.UTF_8)
        }
    }

    fun buildTorSocks(port: Int = 19050): String {
        require(port in 1..65535)
        val outbound = JSONObject()
            .put("type", "socks")
            .put("tag", "proxy")
            .put("version", "5")
            .put("server", "127.0.0.1")
            .put("server_port", port)
        return tunnelConfig(outbound)
    }

    private fun tunnelConfig(outbound: JSONObject): String {
        val tun = JSONObject()
            .put("type", "tun")
            .put("tag", "tun-in")
            .put("interface_name", "hmagsodi0")
            .put("address", JSONArray()
                .put("172.19.0.1/30")
                .put("fdfe:dcba:9876::1/126"))
            .put("mtu", 9000)
            .put("auto_route", true)
            .put("strict_route", true)
            .put("stack", "system")

        val direct = JSONObject().put("type", "direct").put("tag", "direct")
        val dns = JSONObject()
            .put("servers", JSONArray()
                .put(JSONObject()
                    .put("tag", "remote-dns")
                    .put("address", "https://1.1.1.1/dns-query")
                    .put("detour", "proxy"))
                .put(JSONObject()
                    .put("tag", "local-dns")
                    .put("address", "local")))
            .put("final", "remote-dns")
            .put("strategy", "prefer_ipv4")

        val route = JSONObject()
            .put("auto_detect_interface", true)
            .put("final", "proxy")
            .put("rules", JSONArray().put(JSONObject()
                .put("protocol", "dns")
                .put("action", "hijack-dns")))

        return JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("dns", dns)
            .put("inbounds", JSONArray().put(tun))
            .put("outbounds", JSONArray().put(outbound).put(direct))
            .put("route", route)
            .toString()
    }

    private fun serverAddress(settings: JSONObject, protocol: String): String {
        val list = if (protocol == "trojan") settings.getJSONArray("servers")
            else settings.getJSONArray("vnext")
        return list.getJSONObject(0).getString("address")
    }

    private fun serverPort(settings: JSONObject, protocol: String): Int {
        val list = if (protocol == "trojan") settings.getJSONArray("servers")
            else settings.getJSONArray("vnext")
        return list.getJSONObject(0).getInt("port")
    }
}
