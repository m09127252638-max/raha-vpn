package com.raha.vpn

import android.net.VpnService
import libXray.DialerController
import libXray.LibXray
import org.json.JSONObject

/**
 * Thin, secret-safe wrapper around the combined libXray/IPtProxy gomobile runtime.
 * Xray sockets are protected from the Android TUN so they use the underlying network.
 */
class XrayCoreManager {
    @Volatile
    private var vpnService: VpnService? = null

    private val dialerController = object : DialerController {
        override fun protectFd(fd: Long): Boolean {
            return vpnService?.protect(fd.toInt()) ?: false
        }
    }

    fun attach(service: VpnService) {
        vpnService = service
        LibXray.registerDialerController(dialerController)
    }

    fun detach() {
        vpnService = null
    }

    fun convertShareLinksToXrayJson(text: String): JSONObject {
        val response = invoke(
            "convertShareLinksToXrayJson",
            JSONObject().put("text", normalizeShareText(text))
        )
        return response.optJSONObject("data")
            ?: throw IllegalStateException("موتور Xray کانفیگ قابل‌استفاده‌ای پیدا نکرد.")
    }

    fun test(configJson: String) {
        invoke("testXray", JSONObject().put("xrayJson", configJson))
    }

    fun start(configJson: String) {
        invoke("runXray", JSONObject().put("xrayJson", configJson))
        check(isRunning()) { "موتور Xray پس از راه‌اندازی فعال نماند." }
    }

    fun stop() {
        invoke("stopXray")
    }

    fun isRunning(): Boolean =
        invoke("getXrayState").optJSONObject("data")?.optBoolean("running", false) ?: false

    private fun invoke(method: String, payload: JSONObject? = null): JSONObject {
        val request = JSONObject()
            .put("apiVersion", API_VERSION)
            .put("method", method)
        if (payload != null) request.put("payload", payload)

        val response = JSONObject(LibXray.invoke(request.toString()))
        if (!response.optBoolean("success", false)) {
            val safeMessage = when (method) {
                "convertShareLinksToXrayJson" -> "لینک سرور ناقص یا توسط موتور پشتیبانی نمی‌شود."
                "testXray" -> "ساختار کانفیگ برای موتور Xray معتبر نیست."
                "runXray" -> "موتور Xray نتوانست تونل را راه‌اندازی کند."
                "stopXray" -> "موتور Xray نتوانست به‌درستی متوقف شود."
                else -> "خطای داخلی موتور Xray."
            }
            throw IllegalStateException(safeMessage)
        }
        return response
    }

    private fun normalizeShareText(text: String): String =
        text.lineSequence().joinToString("\n") { line ->
            when {
                line.startsWith("socks5://", ignoreCase = true) ->
                    "socks://" + line.substringAfter("://")
                line.startsWith("socks5h://", ignoreCase = true) ->
                    "socks://" + line.substringAfter("://")
                else -> line
            }
        }

    private companion object {
        const val API_VERSION = 3
    }
}
