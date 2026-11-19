package com.raha.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Owns the Android VPN permission, TUN descriptor, Xray lifecycle and Tor bridge.
 * The service reports "connected" only after libXray confirms its core is running.
 */
class RahaVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private val xrayCore = XrayCoreManager()
    private val torBridge = TorBridgeManager(this)

    private var startJob: Job? = null
    private var tunDescriptor: ParcelFileDescriptor? = null
    private var foregroundActive = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val rawConfig = intent.getStringExtra(EXTRA_CONFIG)
                val bridge = intent.getStringExtra(EXTRA_BRIDGE)
                if (rawConfig.isNullOrBlank() && bridge.isNullOrBlank()) {
                    publishStatus(STATUS_FAILED, "کانفیگ یا پل انتخاب‌شده خالی است.")
                    stopSelf(startId)
                    return START_NOT_STICKY
                }

                enterForeground("در حال آماده‌سازی تونل امن…")
                startJob?.cancel()
                startJob = scope.launch {
                    lifecycleMutex.withLock {
                        cleanupResources()
                        try {
                            connect(rawConfig, bridge)
                        } catch (cancelled: CancellationException) {
                            cleanupResources()
                            throw cancelled
                        } catch (_: Throwable) {
                            cleanupResources()
                            publishStatus(STATUS_FAILED, "اتصال برقرار نشد؛ کانفیگ، پل یا دسترسی شبکه را بررسی کن.")
                            leaveForeground()
                            stopSelf()
                        }
                    }
                }
            }

            ACTION_STOP -> {
                startJob?.cancel()
                scope.launch {
                    lifecycleMutex.withLock {
                        cleanupResources()
                        publishStatus(STATUS_DISCONNECTED, "VPN قطع شد.")
                        leaveForeground()
                        stopSelf()
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun connect(rawConfig: String?, bridge: String?) {
        publishStatus(STATUS_CONNECTING, "در حال راه‌اندازی موتور اتصال…")

        val torMode = !bridge.isNullOrBlank()
        val outboundDocument = if (torMode) {
            null
        } else {
            val source = xrayCore.convertShareLinksToXrayJson(rawConfig.orEmpty())
            val hostname = XrayConfigBuilder.outboundServerAddress(source)
            val resolved = resolveServerAddress(hostname)
            XrayConfigBuilder.withResolvedServerAddress(source, resolved)
        }

        val socksAddress = if (torMode) {
            publishStatus(STATUS_CONNECTING, "در حال برقراری مدار Tor و پل obfs4…")
            torBridge.connect(bridge!!)
        } else {
            null
        }

        val descriptor = establishTun(excludeApplication = torMode)
        tunDescriptor = descriptor
        xrayCore.attach(this)

        val config = if (torMode) {
            XrayConfigBuilder.buildTorTunConfig(descriptor.fd, socksAddress!!)
        } else {
            XrayConfigBuilder.buildTunConfig(outboundDocument!!, descriptor.fd, torMode = false)
        }

        // Test the exact TUN-backed config before starting the long-running core.
        xrayCore.test(config)
        xrayCore.start(config)
        check(xrayCore.isRunning()) { "Xray core did not remain running" }

        publishStatus(
            STATUS_CONNECTED,
            if (torMode) {
                "تونل VPN با پل obfs4 فعال شد. ترافیک خود برنامه برای جلوگیری از حلقه از تونل مستثناست."
            } else {
                "تونل VPN فعال شد."
            }
        )
        updateNotification(if (torMode) "VPN متصل با پل obfs4" else "VPN متصل")
    }

    private fun establishTun(excludeApplication: Boolean): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("H.MAGHSODI")
            .setMtu(TUN_MTU)
            .addAddress(IPV4_TUN_ADDRESS, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(IPV4_DNS_ADDRESS)
            .addAddress(IPV6_TUN_ADDRESS, 126)
            .addRoute("::", 0)
            .addDnsServer(IPV6_DNS_ADDRESS)

        if (excludeApplication) {
            // Tor's native daemon must reach bridges outside the TUN. Android
            // filters VPN traffic by UID, so this also excludes this app's own
            // traffic in obfs4 mode; other apps remain routed through the VPN.
            builder.addDisallowedApplication(packageName)
        }

        return builder.establish()
            ?: throw IllegalStateException("Android did not establish the VPN TUN descriptor")
    }

    private suspend fun resolveServerAddress(host: String): String =
        kotlinx.coroutines.withContext(Dispatchers.IO) {
            val candidates = InetAddress.getAllByName(host)
                .filterNot {
                    it.isAnyLocalAddress || it.isLoopbackAddress ||
                        it.isLinkLocalAddress || it.isMulticastAddress
                }
            val selected = candidates.firstOrNull { it is Inet4Address }
                ?: candidates.firstOrNull()
                ?: throw IllegalStateException("سرور به یک نشانی IP قابل‌دسترسی تبدیل نشد.")
            selected.hostAddress.substringBefore('%')
        }

    private suspend fun cleanupResources() {
        runCatching { xrayCore.stop() }
        xrayCore.detach()
        runCatching { tunDescriptor?.close() }
        tunDescriptor = null
        runCatching { torBridge.disconnect() }
    }

    private fun publishStatus(status: String, message: String) {
        val intent = Intent(ACTION_STATUS).setPackage(packageName)
            .putExtra(EXTRA_STATUS, status)
            .putExtra(EXTRA_MESSAGE, message)
        sendBroadcast(intent)
        updateNotification(message)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "H.MAGHSODI VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun enterForeground(message: String) {
        val notification = buildNotification(message)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        foregroundActive = true
    }

    private fun leaveForeground() {
        if (!foregroundActive) return
        leaveForeground()
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        foregroundActive = false
    }

    private fun updateNotification(message: String) {
        if (!foregroundActive) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(message))
    }

    private fun buildNotification(message: String): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("H.MAGHSODI")
            .setContentText(message)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()

    override fun onRevoke() {
        startJob?.cancel()
        scope.launch {
            lifecycleMutex.withLock {
                cleanupResources()
                publishStatus(STATUS_DISCONNECTED, "دسترسی VPN لغو شد.")
                leaveForeground()
                stopSelf()
            }
        }
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onDestroy() {
        startJob?.cancel()
        runCatching {
            runBlocking(Dispatchers.IO) {
                lifecycleMutex.withLock {
                    cleanupResources()
                    leaveForeground()
                }
            }
        }
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.raha.vpn.action.START"
        const val ACTION_STOP = "com.raha.vpn.action.STOP"
        const val ACTION_STATUS = "com.raha.vpn.action.STATUS"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_BRIDGE = "bridge"
        const val EXTRA_STATUS = "status"
        const val EXTRA_MESSAGE = "message"

        const val STATUS_CONNECTING = "connecting"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_DISCONNECTED = "disconnected"
        const val STATUS_FAILED = "failed"

        private const val CHANNEL_ID = "hmaghsodi_vpn"
        private const val NOTIFICATION_ID = 19050
        private const val TUN_MTU = 1400
        private const val IPV4_TUN_ADDRESS = "10.77.0.1"
        private const val IPV4_DNS_ADDRESS = "10.77.0.2"
        private const val IPV6_TUN_ADDRESS = "fd77:77:77::1"
        private const val IPV6_DNS_ADDRESS = "fd77:77:77::2"
    }
}
