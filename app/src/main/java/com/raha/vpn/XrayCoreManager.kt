package com.raha.vpn

import android.content.Context
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Launches the Xray Android/arm64 executable packaged in libxray.so.
 * The process uses the app UID; RahaVpnService excludes that UID from its TUN
 * so Xray's upstream sockets cannot loop back into the VPN.
 */
class XrayCoreManager(context: Context) {
    private val appContext = context.applicationContext
    private var process: Process? = null
    private var configFile: File? = null
    private var logFile: File? = null

    @Synchronized
    suspend fun start(rawConfig: String, socksPort: Int = DEFAULT_SOCKS_PORT): Int {
        stop()
        val config = XrayConfigBuilder.build(rawConfig, socksPort)
        val executable = File(appContext.applicationInfo.nativeLibraryDir, "libxray.so")
        check(executable.isFile && executable.canExecute()) {
            "موتور Xray در این نسخه نصب نشده است؛ فایل libxray.so موجود نیست."
        }
        val config = File(appContext.noBackupFilesDir, "xray-client.json")
        config.writeText(config)
        val output = File(appContext.noBackupFilesDir, "xray-runtime.log")
        configFile = config
        logFile = output
        val child = ProcessBuilder(
            executable.absolutePath,
            "run",
            "-c",
            config.absolutePath
        ).redirectErrorStream(true).redirectOutput(output).start()
        process = child
        try {
            withTimeout(12_000L) {
                while (true) {
                    if (!child.isAlive) {
                        error("موتور Xray پیش از آماده‌شدن متوقف شد؛ گزارش محلی ثبت شد.")
                    }
                    if (canConnect("127.0.0.1", socksPort)) break
                    delay(150)
                }
            }
        } catch (error: Throwable) {
            stop()
            throw error
        }
        return socksPort
    }

    @Synchronized
    fun stop() {
        process?.let { child ->
            runCatching { child.destroy() }
            runCatching {
                if (!child.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
                    child.destroyForcibly()
                    child.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)
                }
            }
        }
        process = null
        configFile?.delete()
        configFile = null
        // Keep only the latest private diagnostic log; it may contain endpoint metadata.
    }

    private fun canConnect(host: String, port: Int): Boolean =
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 250)
            }
            true
        }.getOrDefault(false)

    companion object {
        const val DEFAULT_SOCKS_PORT = 10808
    }
}
