package com.raha.vpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Navy = Color(0xFF071426)
private val Panel = Color(0xFF10243B)
private val Gold = Color(0xFFFFC857)
private val Muted = Color(0xFF9BAFC5)

data class Server(val name: String, val address: String, val protocol: String, val rawConfig: String)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { RahaApp() }
    }
}

@Composable
fun RahaApp() {
    val context = LocalContext.current
    val configStore = remember(context) { ConfigStore(context) }
    val savedServers = remember(configStore) { configStore.load().mapIndexed { index, raw -> serverFromConfig(raw, index) } }
    var selectedTab by remember { mutableStateOf(if (savedServers.isEmpty()) 2 else 0) }
    var configText by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("برای شروع، یک کانفیگ به برنامه اضافه کن.") }
    var servers by remember { mutableStateOf(savedServers) }
    var selectedServer by remember { mutableStateOf(savedServers.firstOrNull { it.protocol == "obfs4" } ?: savedServers.firstOrNull()) }
    var dnsResults by remember { mutableStateOf<List<DnsResult>>(emptyList()) }
    var dnsChecking by remember { mutableStateOf(false) }
    var publicConfigs by remember { mutableStateOf<List<String>>(emptyList()) }
    var configSearching by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        if (savedServers.isEmpty()) {
            configSearching = true
            try {
                val found = withContext(Dispatchers.IO) { PublicConfigSearch.fetch() }
                publicConfigs = found
                val bridgeCount = found.count { it.startsWith("obfs4 ", ignoreCase = true) }
                val proxyCount = found.size - bridgeCount
                message = if (found.isEmpty()) {
                    "از منابع عمومی کانفیگی دریافت نشد؛ اتصال اینترنت یا دسترسی به منابع را بررسی کن."
                } else {
                    "$proxyCount کانفیگ سرور و $bridgeCount پل Tor دریافت شد؛ برای افزودن، گزینه افزودن را بزن."
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                message = "دریافت خودکار کانفیگ ناموفق بود؛ از دکمه جستجوی مجدد استفاده کن."
            } finally {
                configSearching = false
            }
        }
    }
    val torBridgeManager = remember(context) { TorBridgeManager(context.applicationContext) }
    var torConnecting by remember { mutableStateOf(false) }
    var torConnected by remember { mutableStateOf(false) }
    var vpnConnecting by remember { mutableStateOf(false) }
    var vpnConnected by remember { mutableStateOf(false) }
    var pendingSingBoxConfig by remember { mutableStateOf<String?>(null) }
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val config = pendingSingBoxConfig
        pendingSingBoxConfig = null
        if (result.resultCode == Activity.RESULT_OK && !config.isNullOrBlank()) {
            vpnConnecting = true
            SingBoxVpnService.start(context, config)
            message = "درخواست اتصال تونل ارسال شد؛ منتظر تأیید موتور هستیم."
        } else {
            vpnConnecting = false
            message = "مجوز ایجاد تونل VPN داده نشد."
        }
    }

    val wireGuardFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val imported = runCatching {
                context.contentResolver.openInputStream(uri)
                    ?.bufferedReader(Charsets.UTF_8)
                    ?.use { it.readText() }
                    ?: error("خواندن فایل ناموفق بود")
            }.getOrNull()
            when {
                imported.isNullOrBlank() -> message = "فایل خالی است یا خوانده نشد."
                imported.length > 128 * 1024 -> message = "حجم فایل کانفیگ بیش از حد مجاز است."
                !imported.contains("[Interface]", ignoreCase = true) ||
                    !imported.contains("[Peer]", ignoreCase = true) ||
                    !ConfigStore.isSupported(imported) -> message = "فایل انتخاب‌شده، کانفیگ استاندارد WireGuard نیست."
                else -> {
                    configText = imported.trim()
                    selectedTab = 1
                    message = "فایل WireGuard بارگذاری شد؛ برای ذخیره، افزودن به سرورها را بزن."
                }
            }
        }
    }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                vpnConnected = intent?.getBooleanExtra(SingBoxVpnService.EXTRA_CONNECTED, false) == true
                vpnConnecting = false
                val error = intent?.getStringExtra(SingBoxVpnService.EXTRA_ERROR)
                message = if (!error.isNullOrBlank()) error else if (vpnConnected) {
                    "موتور تونل راه‌اندازی شد؛ دسترسی واقعی اینترنت هنوز تأیید نشده است."
                } else {
                    "اتصال VPN قطع شد."
                }
            }
        }
        val filter = IntentFilter(SingBoxVpnService.ACTION_STATE)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            context.registerReceiver(receiver, filter)
        }
        SingBoxVpnService.refreshState(context)
        onDispose { runCatching { context.unregisterReceiver(receiver) } }
    }

    fun requestSingBoxTunnel(config: String) {
        val permissionIntent = VpnService.prepare(context)
        if (permissionIntent == null) {
            vpnConnecting = true
            SingBoxVpnService.start(context, config)
            message = "درخواست اتصال تونل ارسال شد."
        } else {
            pendingSingBoxConfig = config
            vpnConnecting = true
            vpnPermissionLauncher.launch(permissionIntent)
        }
    }

    MaterialTheme(colorScheme = darkColorScheme(background = Navy, surface = Panel, primary = Gold, onPrimary = Navy, onBackground = Color.White, onSurface = Color.White)) {
        Surface(Modifier.fillMaxSize(), color = Navy) {
            Column(Modifier.fillMaxSize().padding(20.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(46.dp).background(Gold, RoundedCornerShape(14.dp)), contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.Shield, null, tint = Navy, modifier = Modifier.size(28.dp))
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("H.MAGHSODI", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text("اتصال آزاد، ساده و امن", color = Muted, fontSize = 12.sp)
                    }
                    Spacer(Modifier.weight(1f))
                    Text("نسخه ۰.۳", color = Gold, fontSize = 12.sp)
                }
                Spacer(Modifier.height(26.dp))
                Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(22.dp)) {
                    Column(Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(Modifier.size(112.dp).background(Color(0xFF183653), CircleShape), contentAlignment = Alignment.Center) {
                            Icon(Icons.Default.Shield, null, tint = Gold, modifier = Modifier.size(54.dp))
                        }
                        Spacer(Modifier.height(14.dp))
                        val isObfs4Selected = selectedServer?.protocol == "obfs4"
                        val isSingBoxSupported = selectedServer?.protocol in setOf("vless", "vmess", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "wireguard", "wg")
                        val isAnyConnected = torConnected || vpnConnected
                        Text(
                            when {
                                vpnConnected && isObfs4Selected -> "موتور تونل Tor راه‌اندازی شده"
                                vpnConnected -> "موتور تونل VPN راه‌اندازی شده"
                                torConnected && isObfs4Selected -> "پل Tor آماده؛ تونل سراسری قطع است"
                                torConnected -> "پروکسی Tor آماده است"
                                torConnecting -> "در حال اتصال به پل obfs4..."
                                vpnConnecting -> "در حال راه‌اندازی تونل VPN..."
                                isObfs4Selected -> "آماده اتصال با پل obfs4"
                                isSingBoxSupported -> "آماده اتصال با ${selectedServer?.protocol?.uppercase()}"
                                selectedServer != null -> "این پروتکل هنوز آماده اتصال نیست"
                                else -> "ابتدا یک سرور اضافه کن"
                            },
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            when {
                                vpnConnected && isObfs4Selected -> "موتور تونل Tor فعال شده؛ عبور موفق اینترنت هنوز جداگانه آزمایش نشده است."
                                vpnConnected -> "موتور sing-box تونل را پذیرفته؛ دسترسی واقعی اینترنت هنوز تأیید نشده است."
                                torConnected -> "پل Tor آماده است؛ برای اتصال سراسری دوباره بزن."
                                selectedServer == null -> "یک کانفیگ VLESS، VMess، Trojan، Shadowsocks، WireGuard یا پل obfs4 اضافه کن."
                                isObfs4Selected -> "اتصال Tor با پل obfs4"
                                isSingBoxSupported -> "سرور انتخاب‌شده: ${selectedServer?.address}"
                                else -> "این نوع کانفیگ هنوز آماده اتصال نیست."
                            },
                            color = Muted,
                            fontSize = 12.sp
                        )
                        Spacer(Modifier.height(16.dp))
                        Button(
                            onClick = {
                                when {
                                    vpnConnected -> {
                                        vpnConnecting = true
                                        SingBoxVpnService.stop(context)
                                        if (torConnected) {
                                            coroutineScope.launch {
                                                withContext(Dispatchers.IO) { torBridgeManager.disconnect() }
                                                torConnected = false
                                            }
                                        }
                                    }
                                    isObfs4Selected -> {
                                        val bridge = selectedServer?.rawConfig
                                        if (bridge.isNullOrBlank()) {
                                            message = "ابتدا یک پل obfs4 معتبر انتخاب کن."
                                        } else if (torConnected) {
                                            runCatching { SingBoxConfigBuilder.buildTorSocks() }
                                                .onSuccess { requestSingBoxTunnel(it) }
                                                .onFailure { message = "ساخت تونل Tor ناموفق بود: ${it.message}" }
                                        } else {
                                            torConnecting = true
                                            coroutineScope.launch {
                                                try {
                                                    withContext(Dispatchers.IO) { torBridgeManager.connect(bridge) }
                                                    torConnected = true
                                                    val config = SingBoxConfigBuilder.buildTorSocks()
                                                    requestSingBoxTunnel(config)
                                                } catch (cancelled: CancellationException) {
                                                    throw cancelled
                                                } catch (error: Exception) {
                                                    torConnected = false
                                                    message = "راه‌اندازی پل یا تونل Tor ناموفق بود: " +
                                                        (error.message ?: "خطای ناشناخته")
                                                } finally {
                                                    torConnecting = false
                                                }
                                            }
                                        }
                                    }
                                    torConnected -> {
                                        torConnecting = true
                                        coroutineScope.launch {
                                            withContext(Dispatchers.IO) { torBridgeManager.disconnect() }
                                            torConnected = false
                                            torConnecting = false
                                            message = "اتصال Tor قطع شد."
                                        }
                                    }
                                    isSingBoxSupported -> {
                                        try {
                                            requestSingBoxTunnel(SingBoxConfigBuilder.build(selectedServer!!.rawConfig))
                                        } catch (error: Throwable) {
                                            message = "کانفیگ قابل اجرا نیست: " + (error.message ?: "خطای نامشخص")
                                        }
                                    }
                                }
                            },
                            enabled = !torConnecting && !vpnConnecting &&
                                (isAnyConnected || isObfs4Selected || isSingBoxSupported),
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                            shape = RoundedCornerShape(14.dp)
                        ) {
                            Text(
                                when {
                                    torConnecting || vpnConnecting -> "در حال اتصال..."
                                    vpnConnected -> "قطع اتصال"
                                    torConnected && isObfs4Selected -> "ادامه اتصال سراسری با Tor"
                                    torConnected -> "قطع اتصال"
                                    isObfs4Selected -> "اتصال سراسری با obfs4"
                                    isSingBoxSupported -> "اتصال VPN سراسری"
                                    selectedServer != null -> "پروتکل پشتیبانی‌نشده"
                                    else -> "سروری انتخاب نشده"
                                }
                            )
                        }
                        Text(
                            when {
                                vpnConnected && isObfs4Selected -> "موتور تونل Tor فعال است؛ عبور واقعی ترافیک هنوز آزمایش نشده."
                                vpnConnected -> "موتور sing-box فعال است؛ عبور واقعی ترافیک هنوز آزمایش نشده."
                                isObfs4Selected -> "ابتدا پل obfs4 راه‌اندازی می‌شود؛ سپس تونل سراسری VPN فعال خواهد شد."
                                else -> "اتصال فقط پس از تأیید موفق موتور و مجوز اندروید فعال اعلام می‌شود."
                            },
                            color = Muted,
                            fontSize = 10.sp
                        )
                    }
                }
                Spacer(Modifier.height(20.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TabButton("سرورها", selectedTab == 0) { selectedTab = 0 }
                    TabButton("افزودن کانفیگ", selectedTab == 1) { selectedTab = 1 }
                    TabButton("جستجو", selectedTab == 2) { selectedTab = 2 }
                }
                Spacer(Modifier.height(14.dp))
                when (selectedTab) {
                    0 -> {
                        Text("سرورهای من", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Spacer(Modifier.height(8.dp))
                        if (servers.isEmpty()) Text("هنوز سروری اضافه نشده است.", color = Muted, modifier = Modifier.padding(vertical = 18.dp))
                        else LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(servers) { server ->
                                Card(colors = CardDefaults.cardColors(containerColor = Panel), modifier = Modifier.fillMaxWidth().clickable { selectedServer = server }) {
                                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                                        Column(Modifier.weight(1f)) {
                                            Text(server.name, fontWeight = FontWeight.SemiBold)
                                            Text(server.protocol + " • " + server.address, color = Muted, fontSize = 12.sp)
                                        }
                                        if (selectedServer == server) Text("انتخاب‌شده", color = Gold, fontSize = 12.sp)
                                        IconButton(onClick = {
                                            configStore.remove(server.rawConfig)
                                            servers = servers.filterNot { it.rawConfig == server.rawConfig }
                                            if (selectedServer?.rawConfig == server.rawConfig) selectedServer = servers.firstOrNull { it.protocol == "obfs4" } ?: servers.firstOrNull()
                                            message = "سرور از فهرست حذف شد."
                                        }) {
                                            Icon(Icons.Default.Delete, contentDescription = "حذف سرور", tint = Muted)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    1 -> {
                        Text("افزودن کانفیگ", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text("لینک سرور یا خط کامل obfs4 را اینجا جای‌گذاری کن.", color = Muted, fontSize = 12.sp)
                        Spacer(Modifier.height(10.dp))
                        OutlinedTextField(value = configText, onValueChange = { configText = it }, modifier = Modifier.fillMaxWidth().height(130.dp), placeholder = { Text("vless://، hysteria2://، tuic://، فایل WireGuard یا obfs4 ...") }, minLines = 4)
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                val subscriptionUrl = configText.trim()
                                if (!subscriptionUrl.startsWith("https://", ignoreCase = true)) {
                                    message = "برای دریافت سابسکریپشن، لینک HTTPS را در کادر بالا وارد کن."
                                } else if (!configSearching) {
                                    configSearching = true
                                    coroutineScope.launch {
                                        try {
                                            val found = withContext(Dispatchers.IO) {
                                                PublicConfigSearch.fetchSubscription(subscriptionUrl)
                                            }
                                            if (found.isEmpty()) {
                                                message = "از این لینک کانفیگ پشتیبانی‌شده‌ای دریافت نشد؛ ممکن است فرمت آن Clash یا لینک نامعتبر باشد."
                                            } else {
                                                found.forEach { configStore.add(it) }
                                                servers = configStore.load().mapIndexed { index, raw -> serverFromConfig(raw, index) }
                                                selectedServer = servers.firstOrNull { it.rawConfig == found.first() } ?: servers.firstOrNull()
                                                configText = ""
                                                message = "${found.size} کانفیگ از سابسکریپشن دریافت و ذخیره شد؛ زنده‌بودن سرورها هنوز بررسی نشده است."
                                                selectedTab = 0
                                            }
                                        } catch (cancelled: CancellationException) {
                                            throw cancelled
                                        } catch (_: Exception) {
                                            message = "دریافت سابسکریپشن ناموفق بود؛ لینک HTTPS یا دسترسی شبکه را بررسی کن."
                                        } finally {
                                            configSearching = false
                                        }
                                    }
                                }
                            },
                            enabled = !configSearching,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(if (configSearching) "در حال دریافت سابسکریپشن..." else "دریافت و ذخیره از لینک سابسکریپشن")
                        }
                        OutlinedButton(
                            onClick = { wireGuardFileLauncher.launch(arrayOf("text/plain", "application/octet-stream", "*/*")) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("انتخاب فایل WireGuard (.conf)")
                        }
                        Spacer(Modifier.height(10.dp))
                        Button(onClick = {
                            val entries = if (configText.contains("[Interface]", ignoreCase = true) && configText.contains("[Peer]", ignoreCase = true)) {
                                listOf(configText.trim())
                            } else {
                                configText.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
                            }
                            val valid = entries.filter { ConfigStore.isSupported(it) }
                            if (valid.isNotEmpty()) {
                                runCatching {
                                    valid.forEach { configStore.add(it) }
                                    servers = configStore.load().mapIndexed { index, raw -> serverFromConfig(raw, index) }
                                    selectedServer = servers.firstOrNull { it.protocol == "obfs4" } ?: servers.firstOrNull()
                                    configText = ""
                                    message = valid.size.toString() + " کانفیگ به‌صورت رمزگذاری‌شده ذخیره شد."
                                    selectedTab = 0
                                }.onFailure {
                                    message = "ذخیره‌سازی امن انجام نشد؛ دوباره تلاش کن."
                                }
                            } else {
                                message = "لینک معتبری پیدا نشد؛ هر لینک را در یک خط وارد کن."
                            }
                        }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Add, null); Spacer(Modifier.width(6.dp)); Text("افزودن به سرورها")
                        }
                    }
                    else -> {
                        Text("جستجوی سرورهای عمومی", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Spacer(Modifier.height(8.dp))
                        Text("بررسی DNSهای عمومی رمزگذاری‌شده (DoH)", color = Muted)
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = {
                                if (!dnsChecking) {
                                    dnsChecking = true
                                    coroutineScope.launch {
                                        try {
                                            dnsResults = withContext(Dispatchers.IO) { DnsProbe.checkAll() }
                                        } catch (cancelled: CancellationException) {
                                            throw cancelled
                                        } catch (_: Exception) {
                                            message = "بررسی DNS با خطا روبه‌رو شد؛ دوباره تلاش کن."
                                        } finally {
                                            dnsChecking = false
                                        }
                                    }
                                }
                            },
                            enabled = !dnsChecking,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Search, null)
                            Spacer(Modifier.width(8.dp))
                            Text(if (dnsChecking) "در حال بررسی..." else "بررسی DNSهای عمومی")
                        }
                        Spacer(Modifier.height(10.dp))
                        dnsResults.forEach { result ->
                            Card(
                                colors = CardDefaults.cardColors(containerColor = Panel),
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                            ) {
                                Row(
                                    Modifier.fillMaxWidth().padding(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(result.provider, fontWeight = FontWeight.SemiBold)
                                        Text(result.detail, color = Muted, fontSize = 12.sp)
                                    }
                                    Text(if (result.reachable) "فعال" else "ناموفق", color = if (result.reachable) Gold else Muted, fontSize = 12.sp)
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Text("این بررسی فقط دسترسی DNS را می‌سنجد و به‌تنهایی فیلترشکن نیست.", color = Muted, fontSize = 11.sp)
                        Text("پل‌های obfs4 با موتور Tor و obfs4proxy داخلی قابل راه‌اندازی‌اند. پل‌های عمومی ممکن است از کار افتاده باشند؛ در صورت شکست، پل دیگری را امتحان کن.", color = Muted, fontSize = 11.sp)
                        Spacer(Modifier.height(14.dp))
                        OutlinedButton(onClick = {
                            if (!configSearching) {
                                configSearching = true
                                coroutineScope.launch {
                                    try {
                                        val found = withContext(Dispatchers.IO) { PublicConfigSearch.fetch() }
                                        publicConfigs = found
                                        val bridgeCount = found.count { it.startsWith("obfs4 ", ignoreCase = true) }
                                        val proxyCount = found.size - bridgeCount
                                        message = if (found.isEmpty()) "کانفیگی دریافت نشد؛ بعداً دوباره تلاش کن." else "$proxyCount کانفیگ سرور و $bridgeCount پل Tor پیدا شد؛ فعال بودن آن‌ها تضمین‌شده نیست."
                                    } catch (cancelled: CancellationException) {
                                        throw cancelled
                                    } catch (_: Exception) {
                                        message = "جستجوی کانفیگ‌ها با خطا روبه‌رو شد؛ دوباره تلاش کن."
                                    } finally {
                                        configSearching = false
                                    }
                                }
                            }
                        }, enabled = !configSearching, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Search, null); Spacer(Modifier.width(8.dp)); Text(if (configSearching) "در حال جستجو..." else "جستجوی کانفیگ‌های عمومی")
                        }
                        if (publicConfigs.size > 25) Text("۲۵ مورد اول نمایش داده می‌شود؛ ${publicConfigs.size} مورد دریافت شد.", color = Muted, fontSize = 11.sp)
                        LazyColumn(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(3.dp)
                        ) {
                            items(publicConfigs.take(25)) { raw ->
                                Card(colors = CardDefaults.cardColors(containerColor = Panel), modifier = Modifier.fillMaxWidth()) {
                                    Row(Modifier.fillMaxWidth().padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                                        Column(Modifier.weight(1f)) {
                                            Text((if (raw.startsWith("obfs4 ", ignoreCase = true)) "OBFS4" else raw.substringBefore("://").uppercase()) + " • کانفیگ عمومی", fontSize = 12.sp)
                                            Text(raw.take(64), color = Muted, fontSize = 10.sp, maxLines = 1)
                                        }
                                        TextButton(onClick = {
                                            runCatching { configStore.add(raw) }.onSuccess {
                                                val updatedServers = configStore.load().mapIndexed { i, item -> serverFromConfig(item, i) }
                                                servers = updatedServers
                                                selectedServer = updatedServers.firstOrNull { it.rawConfig == raw }
                                                    ?: updatedServers.firstOrNull { it.protocol == "obfs4" }
                                                    ?: updatedServers.firstOrNull()
                                                publicConfigs = publicConfigs.filterNot { it == raw }
                                                selectedTab = 0
                                                message = "کانفیگ ذخیره شد؛ برای شروع اتصال دکمه اتصال VPN را بزن."
                                            }.onFailure { message = "ذخیره کانفیگ انجام نشد." }
                                        }) { Text("افزودن", color = Gold) }
                                    }
                                }
                            }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(message, color = Gold, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                Text("امنیت مهم‌تر از اتصال است؛ کانفیگ‌های ناشناس را با احتیاط استفاده کن.", color = Muted, fontSize = 10.sp)
            }
        }
    }
}

@Composable
private fun RowScope.TabButton(label: String, active: Boolean, onClick: () -> Unit) {
    Surface(modifier = Modifier.weight(1f).clickable(onClick = onClick), color = if (active) Gold else Panel, shape = RoundedCornerShape(12.dp)) {
        Text(label, modifier = Modifier.padding(vertical = 12.dp), textAlign = androidx.compose.ui.text.style.TextAlign.Center, color = if (active) Navy else Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}


private fun serverFromConfig(raw: String, index: Int): Server {
    val isObfs4 = raw.startsWith("obfs4 ", ignoreCase = true)
    val isWireGuard = raw.contains("[Interface]", ignoreCase = true) && raw.contains("[Peer]", ignoreCase = true)
    val protocol = when { isObfs4 -> "obfs4"; isWireGuard -> "wireguard"; else -> raw.substringBefore("://", "").lowercase() }
    val endpoint = (if (isWireGuard) {
        Regex("(?im)^\\s*Endpoint\\s*=\\s*(.+)$").find(raw)?.groupValues?.get(1)?.trim()
    } else if (isObfs4) {
        Regex("""^obfs4\s+([^ ]+)""", RegexOption.IGNORE_CASE).find(raw)?.groupValues?.get(1)
    } else {
        Regex("@([^@:/?#]+):\\d+").find(raw)?.groupValues?.get(1)
            ?: Regex("^([a-zA-Z0-9.-]+):\\d+").find(raw.substringAfter("://", ""))?.groupValues?.get(1)
    }) ?: "آدرس مخفی"
    return Server("سرور " + (index + 1), endpoint, protocol, raw)
}
