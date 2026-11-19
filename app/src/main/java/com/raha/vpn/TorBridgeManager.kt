package com.raha.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import org.torproject.jni.TorService
import IPtProxy.Controller
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Runs the Tor daemon with an obfs4 pluggable transport.
 * The returned SOCKS endpoint is a local proxy; this class does not create
 * a device-wide Android VPN tunnel.
 */
class TorBridgeManager(private val context: Context) {
    private var transportController: Controller? = null
    private var started = false

    suspend fun connect(rawBridge: String): String {
        require(ConfigStore.isSupported(rawBridge)) { "خط پل obfs4 معتبر نیست." }
        disconnect()

        val bridge = rawBridge.trim().removePrefix("Bridge ").trim()
        val controller = Controller(
            context.noBackupFilesDir.resolve("iptproxy-state").absolutePath,
            false,
            false,
            "ERROR",
            null
        )
        transportController = controller
        try {
            controller.start("obfs4", "")
            val transportAddress = controller.localAddress("obfs4")
            require(transportAddress.isNotBlank()) { "موتور obfs4 پورت محلی ایجاد نکرد." }

            val torrc = TorService.getTorrc(context)
            torrc.parentFile?.mkdirs()
            torrc.writeText(buildTorrc(bridge, transportAddress))

            awaitTorCircuit()
            started = true
            return "127.0.0.1:9050"
        } catch (error: Throwable) {
            disconnect()
            throw error
        }
    }

    suspend fun disconnect() {
        runCatching { context.stopService(Intent(context, TorService::class.java)) }
        runCatching { transportController?.stop("obfs4") }
        transportController = null
        started = false
    }

    fun isConnected(): Boolean = started

    internal fun buildTorrc(bridge: String, transportAddress: String): String =
        listOf(
            "UseBridges 1",
            "ClientTransportPlugin obfs4 socks5 $transportAddress",
            "Bridge $bridge",
            "SocksPort 127.0.0.1:9050",
            "SafeSocks 1"
        ).joinToString("\\n", postfix = "\\n")

    private suspend fun awaitTorCircuit() = withTimeout(240_000L) {
        suspendCancellableCoroutine<Unit> { continuation ->
            val unregistered = AtomicBoolean(false)
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context?, intent: Intent?) {
                    if (intent?.getStringExtra(TorService.EXTRA_SERVICE_PACKAGE_NAME) != context.packageName) return
                    when (intent.action) {
                        TorService.ACTION_STATUS -> {
                            when (intent.getStringExtra(TorService.EXTRA_STATUS)) {
                                TorService.STATUS_ON -> if (continuation.isActive) continuation.resume(Unit)
                                TorService.STATUS_STOPPING, TorService.STATUS_OFF -> {
                                    if (continuation.isActive) continuation.resumeWithException(
                                        IllegalStateException("Tor نتوانست مدار امن بسازد.")
                                    )
                                }
                            }
                        }
                        TorService.ACTION_ERROR -> {
                            if (continuation.isActive) continuation.resumeWithException(
                                IllegalStateException(intent.getStringExtra(Intent.EXTRA_TEXT) ?: "خطای راه‌اندازی Tor")
                            )
                        }
                    }
                }
            }
            fun unregister() {
                if (unregistered.compareAndSet(false, true)) {
                    runCatching { context.unregisterReceiver(receiver) }
                }
            }
            val filter = IntentFilter().apply {
                addAction(TorService.ACTION_STATUS)
                addAction(TorService.ACTION_ERROR)
            }
            try {
                if (Build.VERSION.SDK_INT >= 33) {
                    context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
                } else {
                    @Suppress("DEPRECATION")
                    context.registerReceiver(receiver, filter)
                }
                continuation.invokeOnCancellation { unregister() }
                context.startService(Intent(context, TorService::class.java))
            } catch (error: Throwable) {
                unregister()
                if (continuation.isActive) continuation.resumeWithException(error)
            }
            continuation.invokeOnCancellation { unregister() }
        }
    }
}
