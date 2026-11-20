package com.raha.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import org.torproject.jni.TorService
import io.nekohasekai.IPtProxy.Controller
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.EOFException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
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

        val bridge = ConfigStore.normalizeObfs4Bridge(rawBridge)
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

            awaitTorServiceStarted()
            awaitTorCircuitReady()
            started = true
            return "127.0.0.1:19050"
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

    /**
     * STATUS_ON only means the Android service started. Wait until a SOCKS5
     * CONNECT succeeds through Tor, which requires a working circuit and exit.
     */
    private suspend fun awaitTorCircuitReady() = withTimeout(180_000L) {
        while (true) {
            val connected = withContext(Dispatchers.IO) {
                runCatching { probeTorSocksCircuit() }.getOrDefault(false)
            }
            if (connected) return@withTimeout
            delay(3_000L)
        }
        @Suppress("UNREACHABLE_CODE")
        Unit
    }

    private fun probeTorSocksCircuit(): Boolean {
        val host = "check.torproject.org"
        val hostBytes = host.toByteArray(StandardCharsets.US_ASCII)
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", 19050), 5_000)
            socket.soTimeout = 7_000
            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            output.write(byteArrayOf(5, 1, 0))
            output.flush()
            if (input.read() != 5 || input.read() != 0) return false

            output.write(byteArrayOf(5, 1, 0, 3, hostBytes.size.toByte()))
            output.write(hostBytes)
            output.write(byteArrayOf(1, -69)) // TCP port 443
            output.flush()
            return consumeSocks5ConnectReply(input)
        }
    }

    companion object {
        internal fun buildTorrc(bridge: String, transportAddress: String): String =
            listOf(
                "UseBridges 1",
                "ClientTransportPlugin obfs4 socks5 $transportAddress",
                "Bridge $bridge",
                "SocksPort 0",
                "SocksPort 127.0.0.1:19050",
                "SafeSocks 1"
            ).joinToString("\n", postfix = "\n")

        internal fun consumeSocks5ConnectReply(input: InputStream): Boolean = runCatching {
            if (input.read() != 5) return@runCatching false
            if (input.read() != 0) return@runCatching false
            if (input.read() != 0) return@runCatching false
            when (input.read()) {
                1 -> repeat(4) { if (input.read() < 0) throw EOFException() }
                3 -> {
                    val length = input.read()
                    if (length < 0) throw EOFException()
                    repeat(length) { if (input.read() < 0) throw EOFException() }
                }
                4 -> repeat(16) { if (input.read() < 0) throw EOFException() }
                else -> return@runCatching false
            }
            if (input.read() < 0 || input.read() < 0) throw EOFException()
            true
        }.getOrDefault(false)
    }

    private suspend fun awaitTorServiceStarted() = withTimeout(240_000L) {
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
                                        IllegalStateException("سرویس Tor پیش از آماده‌شدن متوقف شد.")
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
