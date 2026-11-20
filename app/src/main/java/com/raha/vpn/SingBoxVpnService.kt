package com.raha.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import java.net.InetAddress
import java.util.concurrent.Executors

/**
 * Owns the Android TUN descriptor and the sing-box command server.
 * A connection is considered active only after startOrReloadService succeeds.
 */
class SingBoxVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor()
    @Volatile private var commandServer: CommandServer? = null
    @Volatile private var tunDescriptor: android.os.ParcelFileDescriptor? = null
    @Volatile private var latestStartId: Int = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                latestStartId = startId
                executor.execute {
                    stopTunnel()
                    stopSelfResult(startId)
                }
                return START_NOT_STICKY
            }
            ACTION_QUERY_STATE -> {
                executor.execute {
                    val active = commandServer != null
                    broadcastState(connected = active)
                    if (!active) stopSelfResult(startId)
                }
                return START_NOT_STICKY
            }
            ACTION_START -> {
                latestStartId = startId
                val config = intent.getStringExtra(EXTRA_CONFIG)
                if (config.isNullOrBlank()) {
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                enterForeground()
                executor.execute { startTunnel(config, startId) }
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent): IBinder? {
        val systemBinder = super.onBind(intent)
        return systemBinder
    }

    override fun onRevoke() {
        val revokeStartId = latestStartId
        executor.execute {
            stopTunnel()
            stopSelfResult(revokeStartId)
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        executor.execute { stopTunnel() }
        executor.shutdown()
        super.onDestroy()
    }

    private fun enterForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "VPN connection", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("H.MAGHSODI VPN")
            .setContentText("در حال برقراری تونل امن")
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun startTunnel(config: String, startId: Int) {
        try {
            releaseTunnel()
            val base = filesDir
            val setup = SetupOptions().apply {
                basePath = base.absolutePath
                workingPath = getExternalFilesDir(null)?.absolutePath ?: filesDir.absolutePath
                tempPath = cacheDir.absolutePath
                fixAndroidStack = true
                logMaxLines = 500
                debug = false
                crashReportSource = "H.MAGHSODI"
                appVersion = BuildConfig.VERSION_CODE.toString()
                appMarketingVersion = BuildConfig.VERSION_NAME
            }
            LibboxRuntimeSetup.ensure(setup)
            val platform = createPlatformInterface()
            val handler = object : CommandServerHandler {
                override fun serviceStop() {
                    // Bind this callback to the start request that created its CommandServer.
                    val stopId = startId
                    executor.execute {
                        // A delayed stop from an older CommandServer must not tear
                        // down a newer connection request queued in the meantime.
                        if (stopId != latestStartId) {
                            Log.i(TAG, "Ignoring stale sing-box stop request")
                            return@execute
                        }
                        stopTunnel()
                        stopSelfResult(stopId)
                    }
                }

                override fun serviceReload() {
                    Log.i(TAG, "sing-box requested a service reload")
                }

                override fun getSystemProxyStatus(): SystemProxyStatus {
                    return SystemProxyStatus().apply {
                        available = false
                        enabled = false
                    }
                }

                override fun setSystemProxyEnabled(enabled: Boolean) = Unit
                override fun triggerNativeCrash() = Unit
                override fun writeDebugMessage(message: String?) {
                    Log.d(TAG, message.orEmpty())
                }
                override fun connectSSHAgent(): Int = -1
            }
            val server = CommandServer(handler, platform)
            commandServer = server
            server.start()
            server.startOrReloadService(config, OverrideOptions())
            broadcastState(connected = true)
            Log.i(TAG, "sing-box tunnel started")
        } catch (error: Throwable) {
            Log.e(TAG, "Unable to start sing-box tunnel", error)
            broadcastState(connected = false, error = error.message ?: "خطای راه‌اندازی تونل")
            stopTunnel(broadcast = false)
            stopSelfResult(startId)
        }
    }

    private fun createPlatformInterface(): PlatformInterface {
        return SingBoxPlatformInterface(
            context = this,
            protectSocket = { fd -> protect(fd) },
            openTun = { options -> establishTun(options) }
        )
    }

    private fun establishTun(options: TunOptions): Int {
        if (VpnService.prepare(this) != null) error("VPN permission has not been granted")
        val builder = Builder().setSession("H.MAGHSODI").setMtu(options.mtu)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        val ipv4 = options.inet4Address
        var hasIpv4Address = false
        while (ipv4.hasNext()) {
            val prefix = ipv4.next()
            builder.addAddress(prefix.address(), prefix.prefix())
            hasIpv4Address = true
        }
        val ipv6 = options.inet6Address
        var hasIpv6Address = false
        while (ipv6.hasNext()) {
            val prefix = ipv6.next()
            builder.addAddress(prefix.address(), prefix.prefix())
            hasIpv6Address = true
        }
        if (options.autoRoute) {
            if (options.dnsMode.value != Libbox.DNSModeDisabled) {
                val dns = options.dnsServerAddress
                while (dns.hasNext()) builder.addDnsServer(dns.next())
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val ipv4Routes = options.inet4RouteAddress
                if (ipv4Routes.hasNext()) {
                    while (ipv4Routes.hasNext()) {
                        val route = ipv4Routes.next()
                        builder.addRoute(IpPrefix(InetAddress.getByName(route.address()), route.prefix()))
                    }
                } else if (hasIpv4Address) {
                    builder.addRoute("0.0.0.0", 0)
                }

                val ipv6Routes = options.inet6RouteAddress
                if (ipv6Routes.hasNext()) {
                    while (ipv6Routes.hasNext()) {
                        val route = ipv6Routes.next()
                        builder.addRoute(IpPrefix(InetAddress.getByName(route.address()), route.prefix()))
                    }
                } else if (hasIpv6Address) {
                    builder.addRoute("::", 0)
                }

                val ipv4Excludes = options.inet4RouteExcludeAddress
                while (ipv4Excludes.hasNext()) {
                    val route = ipv4Excludes.next()
                    builder.excludeRoute(IpPrefix(InetAddress.getByName(route.address()), route.prefix()))
                }
                val ipv6Excludes = options.inet6RouteExcludeAddress
                while (ipv6Excludes.hasNext()) {
                    val route = ipv6Excludes.next()
                    builder.excludeRoute(IpPrefix(InetAddress.getByName(route.address()), route.prefix()))
                }
            } else {
                val ipv4Routes = options.inet4RouteRange
                var hasIpv4Route = false
                while (ipv4Routes.hasNext()) {
                    val route = ipv4Routes.next()
                    builder.addRoute(route.address(), route.prefix())
                    hasIpv4Route = true
                }
                // Older Android versions do not expose excludeRoute(). If sing-box
                // supplies no explicit ranges, still install the default route so
                // the TUN does not come up without carrying IPv4 traffic.
                if (!hasIpv4Route && hasIpv4Address) {
                    builder.addRoute("0.0.0.0", 0)
                }

                val ipv6Routes = options.inet6RouteRange
                var hasIpv6Route = false
                while (ipv6Routes.hasNext()) {
                    val route = ipv6Routes.next()
                    builder.addRoute(route.address(), route.prefix())
                    hasIpv6Route = true
                }
                if (!hasIpv6Route && hasIpv6Address) {
                    builder.addRoute("::", 0)
                }
            }
        }
        val descriptor = builder.establish() ?: error("Android refused to establish the VPN interface")
        tunDescriptor?.close()
        tunDescriptor = descriptor
        return descriptor.fd
    }

    private fun broadcastState(connected: Boolean, error: String? = null) {
        sendBroadcast(Intent(ACTION_STATE).setPackage(packageName)
            .putExtra(EXTRA_CONNECTED, connected)
            .putExtra(EXTRA_ERROR, error))
    }

    private fun releaseTunnel() {
        runCatching { commandServer?.closeService() }
        runCatching { commandServer?.close() }
        commandServer = null
        runCatching { tunDescriptor?.close() }
        tunDescriptor = null
    }

    private fun stopTunnel(broadcast: Boolean = true) {
        releaseTunnel()
        if (broadcast) broadcastState(connected = false)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        private const val TAG = "SingBoxVpnService"
        private const val CHANNEL_ID = "hmagsodi-vpn"
        private const val NOTIFICATION_ID = 7314
        const val ACTION_STATE = "com.raha.vpn.action.STATE"
        const val EXTRA_CONNECTED = "connected"
        const val EXTRA_ERROR = "error"
        private const val ACTION_START = "com.raha.vpn.action.START"
        private const val ACTION_STOP = "com.raha.vpn.action.STOP"
        private const val ACTION_QUERY_STATE = "com.raha.vpn.action.QUERY_STATE"
        private const val EXTRA_CONFIG = "singbox_config"

        fun refreshState(context: Context) {
            context.startService(
                Intent(context, SingBoxVpnService::class.java).setAction(ACTION_QUERY_STATE)
            )
        }

        fun start(context: Context, singBoxConfig: String) {
            val intent = Intent(context, SingBoxVpnService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_CONFIG, singBoxConfig)
            androidx.core.content.ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, SingBoxVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}


private object LibboxRuntimeSetup {
    @Volatile private var initialized = false

    @Synchronized
    fun ensure(options: SetupOptions) {
        if (initialized) return
        Libbox.setup(options)
        initialized = true
    }
}
