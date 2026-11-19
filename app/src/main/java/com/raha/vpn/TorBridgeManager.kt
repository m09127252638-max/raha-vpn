package com.raha.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import go.libXray.LibXray
import go.libXray.PTController
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import org.torproject.jni.TorService
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Starts the Tor daemon with IPtProxy's obfs4 transport and exposes its local
 * SOCKS endpoint to the Xray TUN engine. It does not create the Android VPN.
 */
class TorBridgeManager(private val context: Context) {
    private var transportController: PTController? = null
    private var started = false
    private var torStartRequested = false

    suspend fun connect(rawBridge: String): String {
        require(ConfigStore.isSupported(rawBridge)) { "خط پل obfs4 معتبر نیست." }
        disconnect()

        val withoutBridgePrefix = rawBridge.trim()
            .replaceFirst(Regex("^Bridge\\s+", RegexOption.IGNORE_CASE), "")
        val bridge = withoutBridgePrefix
            .replaceFirst(Regex("^obfs4\\s+", RegexOption.IGNORE_CASE), "obfs4 ")

        val controller = LibXray.newPTController(
            context.noBackupFilesDir.resolve("iptproxy-state").absolutePath
        )
        transportController = controller
        try {
            val transportAddress = controller.startObfs4()
            require(transportAddress.isNotBlank()) { "موتور obfs4 پورت محلی ایجاد نکرد." }

            val torrc = TorService.getTorrc(context)
            torrc.parentFile?.mkdirs()
            torrc.writeText(buildTorrc(bridge, transportAddress))

            awaitTorCircuit()
            started = true
            return "127.0.0.1:19050"
        } catch (error: Throwable) {
            disconnect()
            throw error
        }
    }

    suspend fun disconnect() {
        if (torStartRequested) {
            runCatching {
                withTimeout(15_000L) {
                    awaitTorStopped()
                    // TorService broadcasts OFF from onDestroy after signalling its
                    // native thread. Give runMain time to release its process lock.
                    delay(1_500L)
                }
            }
        } else {
            runCatching { context.stopService(Intent(context, TorService::class.java)) }
        }
        runCatching { transportController?.close() }
        transportController = null
        torStartRequested = false
        started = false
    }

    fun isConnected(): Boolean = started

    internal fun buildTorrc(bridge: String, transportAddress: String): String =
        listOf(
            "UseBridges 1",
            "ClientTransportPlugin obfs4 socks5 $transportAddress",
            "Bridge $bridge",
            "SocksPort 0",
            "SocksPort 127.0.0.1:19050",
            "SafeSocks 1"
        ).joinToString("\n", postfix = "\n")

    private suspend fun awaitTorCircuit() = withTimeout(240_000L) {
        suspendCancellableCoroutine<Unit> { continuation ->
            val unregistered = AtomicBoolean(false)
            var receiver: BroadcastReceiver? = null
            fun unregister() {
                if (unregistered.compareAndSet(false, true)) {
                    receiver?.let { registered ->
                        runCatching { context.unregisterReceiver(registered) }
                    }
                }
            }

            val receiverInstance = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context?, intent: Intent?) {
                    if (intent?.getStringExtra(TorService.EXTRA_SERVICE_PACKAGE_NAME) != context.packageName) return
                    when (intent.action) {
                        TorService.ACTION_STATUS -> {
                            when (intent.getStringExtra(TorService.EXTRA_STATUS)) {
                                // TorService emits ON only after its first circuit is established.
                                TorService.STATUS_ON -> if (continuation.isActive) {
                                    unregister()
                                    continuation.resume(Unit)
                                }
                                TorService.STATUS_STOPPING, TorService.STATUS_OFF -> {
                                    if (continuation.isActive) {
                                        unregister()
                                        continuation.resumeWithException(
                                            IllegalStateException("Tor نتوانست مدار امن بسازد.")
                                        )
                                    }
                                }
                            }
                        }
                        TorService.ACTION_ERROR -> {
                            if (continuation.isActive) {
                                unregister()
                                continuation.resumeWithException(
                                    IllegalStateException(
                                        intent.getStringExtra(Intent.EXTRA_TEXT) ?: "خطای راه‌اندازی Tor"
                                    )
                                )
                            }
                        }
                    }
                }
            }
            receiver = receiverInstance
            val filter = IntentFilter().apply {
                addAction(TorService.ACTION_STATUS)
                addAction(TorService.ACTION_ERROR)
            }

            try {
                if (Build.VERSION.SDK_INT >= 33) {
                    context.registerReceiver(receiverInstance, filter, Context.RECEIVER_NOT_EXPORTED)
                } else {
                    @Suppress("DEPRECATION")
                    context.registerReceiver(receiverInstance, filter)
                }
                continuation.invokeOnCancellation { unregister() }
                torStartRequested = true
                val startedService = context.startService(Intent(context, TorService::class.java))
                check(startedService != null) { "TorService could not be started" }
            } catch (error: Throwable) {
                unregister()
                if (continuation.isActive) continuation.resumeWithException(error)
            }
        }
    }

    private suspend fun awaitTorStopped() = suspendCancellableCoroutine<Unit> { continuation ->
        val unregistered = AtomicBoolean(false)
        var receiver: BroadcastReceiver? = null
        fun unregister() {
            if (unregistered.compareAndSet(false, true)) {
                receiver?.let { registered ->
                    runCatching { context.unregisterReceiver(registered) }
                }
            }
        }

        val receiverInstance = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.getStringExtra(TorService.EXTRA_SERVICE_PACKAGE_NAME) != context.packageName) return
                if (intent.action == TorService.ACTION_STATUS &&
                    intent.getStringExtra(TorService.EXTRA_STATUS) == TorService.STATUS_OFF &&
                    continuation.isActive
                ) {
                    unregister()
                    continuation.resume(Unit)
                }
            }
        }
        receiver = receiverInstance
        try {
            val filter = IntentFilter(TorService.ACTION_STATUS)
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(receiverInstance, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                context.registerReceiver(receiverInstance, filter)
            }
            continuation.invokeOnCancellation { unregister() }
            val stopped = context.stopService(Intent(context, TorService::class.java))
            if (!stopped && continuation.isActive) {
                unregister()
                continuation.resume(Unit)
            }
        } catch (error: Throwable) {
            unregister()
            if (continuation.isActive) continuation.resumeWithException(error)
        }
    }
}
