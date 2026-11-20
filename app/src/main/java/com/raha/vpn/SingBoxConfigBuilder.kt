package com.raha.vpn

import org.json.JSONArray
import org.json.JSONObject

/**
 * Converts supported share links into a sing-box 1.14 client configuration.
 * Credentials are kept in-memory and must never be logged.
 */
object SingBoxConfigBuilder {
    fun build(raw: String): String {
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
