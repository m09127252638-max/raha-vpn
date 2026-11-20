package com.raha.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import java.lang.reflect.Proxy
import java.util.concurrent.Executors

/**
 * Owns the Android TUN descriptor and the sing-box command server.
 * A connection is considered active only after startOrReloadService succeeds.
 */
class SingBoxVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor()
    @Volatile private var commandServer: CommandServer? = null
    @Volatile private var tunDescriptor: android.os.ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                executor.execute { stopTunnel() }
                return START_NOT_STICKY
            }
            ACTION_START -> {
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
        executor.execute { stopTunnel() }
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
                logMaxLines = 500
                debug = false
                appVersion = BuildConfig.VERSION_CODE.toString()
                appMarketingVersion = BuildConfig.VERSION_NAME
            }
            Libbox.setup(setup)
            val platform = createPlatformInterface()
            val handler = object : CommandServerHandler {
                override fun serviceStop() {
                    stopSelf()
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
            server.start()
            server.startOrReloadService(config, OverrideOptions())
            commandServer = server
            Log.i(TAG, "sing-box tunnel started")
        } catch (error: Throwable) {
            Log.e(TAG, "Unable to start sing-box tunnel", error)
            stopTunnel()
            stopSelf(startId)
        }
    }

    private fun createPlatformInterface(): PlatformInterface {
        return Proxy.newProxyInstance(
            PlatformInterface::class.java.classLoader,
            arrayOf(PlatformInterface::class.java)
        ) { _, method, args ->
            when (method.name) {
                "usePlatformAutoDetectInterfaceControl" -> true
                "autoDetectInterfaceControl" -> {
                    val fd = (args?.getOrNull(0) as? Number)?.toInt()
                    if (fd != null && !protect(fd)) error("Unable to protect sing-box socket")
                    null
                }
                "openTun" -> establishTun(args?.getOrNull(0) as TunOptions)
                "getInterfaces" -> emptyInterfaceIterator()
                "findConnectionOwner" -> ConnectionOwner()
                "underNetworkExtension", "includeAllNetworks", "usePlatformShell",
                "usePlatformBridge" -> false
                "tailscaleHostname" -> Build.MODEL ?: "Android"
                "localDNSTransport", "readWIFIState", "openShellSession", "lookupUser",
                "lookupSFTPServer", "readSystemSSHHostKey", "createBridge" -> null
                "toString" -> "H.MAGHSODI sing-box PlatformInterface"
                "hashCode" -> System.identityHashCode(this)
                "equals" -> this === args?.getOrNull(0)
                else -> null
            }
        } as PlatformInterface
    }

    private fun establishTun(options: TunOptions): Int {
        if (VpnService.prepare(this) != null) error("VPN permission has not been granted")
        val builder = Builder().setSession("H.MAGHSODI").setMtu(options.mtu)
        val ipv4 = options.inet4Address
        while (ipv4.hasNext()) {
            val prefix = ipv4.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }
        val ipv6 = options.inet6Address
        while (ipv6.hasNext()) {
            val prefix = ipv6.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }
        if (options.autoRoute) {
            val dns = options.dnsServerAddress
            while (dns.hasNext()) builder.addDnsServer(dns.next())
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }
        val descriptor = builder.establish() ?: error("Android refused to establish the VPN interface")
        tunDescriptor?.close()
        tunDescriptor = descriptor
        return descriptor.fd
    }

    private fun emptyInterfaceIterator(): NetworkInterfaceIterator {
        return Proxy.newProxyInstance(
            NetworkInterfaceIterator::class.java.classLoader,
            arrayOf(NetworkInterfaceIterator::class.java)
        ) { _, method, _ ->
            when (method.name) {
                "hasNext" -> false
                "next" -> null
                else -> null
            }
        } as NetworkInterfaceIterator
    }

    private fun releaseTunnel() {
        runCatching { commandServer?.closeService() }
        runCatching { commandServer?.close() }
        commandServer = null
        runCatching { tunDescriptor?.close() }
        tunDescriptor = null
    }

    private fun stopTunnel() {
        releaseTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        private const val TAG = "SingBoxVpnService"
        private const val CHANNEL_ID = "hmagsodi-vpn"
        private const val NOTIFICATION_ID = 7314
        private const val ACTION_START = "com.raha.vpn.action.START"
        private const val ACTION_STOP = "com.raha.vpn.action.STOP"
        private const val EXTRA_CONFIG = "singbox_config"

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
