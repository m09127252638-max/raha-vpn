package com.raha.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.system.OsConstants
import io.nekohasekai.libbox.BridgeOptions
import io.nekohasekai.libbox.BridgeSession
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NeighborUpdateListener
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.PlatformUser
import io.nekohasekai.libbox.ShellSession
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface as JavaNetworkInterface
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Android platform bridge for sing-box. It supplies the TUN fd, protects
 * proxy sockets from VPN recursion, and reports physical network interfaces.
 */
internal class SingBoxPlatformInterface(
    private val context: Context,
    private val protectSocket: (Int) -> Boolean,
    private val openTun: (TunOptions) -> Int
) : PlatformInterface {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val callbacks = ConcurrentHashMap<InterfaceUpdateListener, ConnectivityManager.NetworkCallback>()
    private val ownInterfaces = ConcurrentHashMap.newKeySet<String>()

    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        check(protectSocket(fd)) { "Unable to protect sing-box socket from VPN routing" }
    }

    override fun openTun(options: TunOptions): Int = openTun.invoke(options)

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int
    ): ConnectionOwner {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return ConnectionOwner()
        }
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort)
        )
        check(uid != Process.INVALID_UID) { "Connection owner was not found" }
        val packages = context.packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        return ConnectionOwner().apply {
            userId = uid
            userName = packages.firstOrNull().orEmpty()
            setAndroidPackageNames(StringArray(packages))
        }
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        closeDefaultInterfaceMonitor(listener)
        var currentDefault: Network? = null
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                currentDefault = network
                publishDefaultNetwork(listener, network)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (currentDefault == null || currentDefault == network) {
                    currentDefault = network
                    publishDefaultNetwork(listener, network)
                }
            }

            override fun onLost(network: Network) {
                if (currentDefault == network) {
                    currentDefault = null
                    listener.updateDefaultInterface("", -1, false, false)
                }
            }
        }
        callbacks[listener] = callback
        connectivity.registerDefaultNetworkCallback(callback)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        callbacks.remove(listener)?.let { callback ->
            runCatching { connectivity.unregisterNetworkCallback(callback) }
        }
    }

    private fun publishDefaultNetwork(listener: InterfaceUpdateListener, network: Network) {
        val properties = connectivity.getLinkProperties(network) ?: return
        val name = properties.interfaceName ?: return
        if (name in ownInterfaces) return
        val nativeInterface = runCatching { JavaNetworkInterface.getByName(name) }.getOrNull()
        val capabilities = connectivity.getNetworkCapabilities(network)
        val metered = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true
        val constrained = Build.VERSION.SDK_INT >= 28 &&
            capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED) == false
        listener.updateDefaultInterface(name, nativeInterface?.index ?: -1, metered, constrained)
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val nativeInterfaces = runCatching {
            Collections.list(JavaNetworkInterface.getNetworkInterfaces())
        }.getOrDefault(mutableListOf())
        val result = mutableListOf<io.nekohasekai.libbox.NetworkInterface>()
        for (network in connectivity.allNetworks) {
            val properties = connectivity.getLinkProperties(network) ?: continue
            val capabilities = connectivity.getNetworkCapabilities(network) ?: continue
            val name = properties.interfaceName ?: continue
            if (name in ownInterfaces) continue
            val native = nativeInterfaces.firstOrNull { it.name == name } ?: continue
            val item = io.nekohasekai.libbox.NetworkInterface().apply {
                this.name = name
                index = native.index
                mtu = runCatching { native.mtu }.getOrDefault(0)
                dnsServer = StringArray(properties.dnsServers.mapNotNull { it.hostAddress })
                gateway = StringArray(
                    properties.routes
                        .filter { it.destination.prefixLength == 0 }
                        .mapNotNull { it.gateway }
                        .filterNot { it.isAnyLocalAddress }
                        .mapNotNull { it.hostAddress }
                )
                addresses = StringArray(native.interfaceAddresses.map { address ->
                    val host = if (address.address is Inet6Address) {
                        address.address.hostAddress.substringBefore('%')
                    } else {
                        address.address.hostAddress
                    }
                    "$host/${address.networkPrefixLength}"
                })
                type = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                    else -> Libbox.InterfaceTypeOther
                }
                var interfaceFlags = 0
                if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    interfaceFlags = OsConstants.IFF_UP or OsConstants.IFF_RUNNING
                }
                if (native.isLoopback) interfaceFlags = interfaceFlags or OsConstants.IFF_LOOPBACK
                if (native.isPointToPoint) interfaceFlags = interfaceFlags or OsConstants.IFF_POINTOPOINT
                if (native.supportsMulticast()) interfaceFlags = interfaceFlags or OsConstants.IFF_MULTICAST
                flags = interfaceFlags
                metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }
            result.add(item)
        }
        return NetworkInterfaceArray(result.iterator())
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun readWIFIState(): WIFIState? = null
    override fun clearDNSCache() = Unit
    override fun sendNotification(notification: Notification) = Unit
    override fun cancelNotification(identifier: String, typeID: Int) = Unit
    override fun startNeighborMonitor(listener: NeighborUpdateListener) = Unit
    override fun closeNeighborMonitor(listener: NeighborUpdateListener) = Unit
    override fun registerMyInterface(name: String) {
        ownInterfaces.add(name)
    }
    override fun usePlatformShell(): Boolean = false
    override fun checkPlatformShell() {
        error("Platform shell is not available in this app")
    }
    override fun openShellSession(
        user: PlatformUser?,
        command: String?,
        environ: StringIterator?,
        term: String?,
        rows: Int,
        cols: Int
    ): ShellSession {
        error("Platform shell is not available in this app")
    }
    override fun lookupUser(username: String?): PlatformUser {
        error("User lookup is not available in this app")
    }
    override fun lookupSFTPServer(): String {
        error("SFTP is not available in this app")
    }
    override fun readSystemSSHHostKey(): String {
        error("SSH host key access is not available in this app")
    }
    override fun tailscaleHostname(): String = Build.MODEL ?: "Android"
    override fun usePlatformBridge(): Boolean = false
    override fun createBridge(options: BridgeOptions?): BridgeSession {
        error("Platform bridge is not available in this app")
    }

    private class StringArray(private val values: List<String>) : StringIterator {
        private var index = 0
        override fun len(): Int = values.size
        override fun hasNext(): Boolean = index < values.size
        override fun next(): String = values[index++]
    }

    private class NetworkInterfaceArray(
        private val iterator: Iterator<io.nekohasekai.libbox.NetworkInterface>
    ) : NetworkInterfaceIterator {
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): io.nekohasekai.libbox.NetworkInterface = iterator.next()
    }
}
