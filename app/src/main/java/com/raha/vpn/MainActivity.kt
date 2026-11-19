package com.raha.vpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
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
    var selectedTab by remember { mutableStateOf(0) }
    var configText by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("برای شروع، یک کانفیگ به برنامه اضافه کن.") }
    var servers by remember { mutableStateOf(savedServers) }
    var selectedServer by remember { mutableStateOf(savedServers.firstOrNull()) }
    var dnsResults by remember { mutableStateOf<List<DnsResult>>(emptyList()) }
    var dnsChecking by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

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
                    Text("نسخه ۰.۲", color = Gold, fontSize = 12.sp)
                }
                Spacer(Modifier.height(26.dp))
                Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(22.dp)) {
                    Column(Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(Modifier.size(112.dp).background(Color(0xFF183653), CircleShape), contentAlignment = Alignment.Center) {
                            Icon(Icons.Default.Shield, null, tint = Gold, modifier = Modifier.size(54.dp))
                        }
                        Spacer(Modifier.height(14.dp))
                        Text("هنوز متصل نیستی", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                        Text("موتور اتصال در مرحله بعد اضافه می‌شود", color = Muted, fontSize = 12.sp)
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = { message = "اتصال هنوز فعال نشده؛ ابتدا موتور امن VPN باید به پروژه اضافه شود." }, enabled = false, modifier = Modifier.fillMaxWidth().height(50.dp), shape = RoundedCornerShape(14.dp)) { Text("اتصال") }
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
                        else LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
                                            if (selectedServer?.rawConfig == server.rawConfig) selectedServer = servers.firstOrNull()
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
                        Text("متن کانفیگ‌های پشتیبانی‌شده را اینجا جای‌گذاری کن.", color = Muted, fontSize = 12.sp)
                        Spacer(Modifier.height(10.dp))
                        OutlinedTextField(value = configText, onValueChange = { configText = it }, modifier = Modifier.fillMaxWidth().height(130.dp), placeholder = { Text("vless:// یا vmess:// یا trojan:// یا hysteria2://") }, minLines = 4)
                        Spacer(Modifier.height(10.dp))
                        Button(onClick = {
                            val entries = configText.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
                            val valid = entries.filter { ConfigStore.isSupported(it) }
                            if (valid.isNotEmpty()) {
                                runCatching {
                                    valid.forEach { configStore.add(it) }
                                    servers = configStore.load().mapIndexed { index, raw -> serverFromConfig(raw, index) }
                                    selectedServer = servers.firstOrNull()
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
                                        val results = withContext(Dispatchers.IO) { DnsProbe.checkAll() }
                                        dnsResults = results
                                        dnsChecking = false
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
                        Spacer(Modifier.height(14.dp))
                        OutlinedButton(onClick = { message = "جستجوی کانفیگ‌های عمومی هنوز در حال آماده‌سازی است؛ کانفیگ ناشناس بدون اعتبارسنجی اضافه نمی‌شود." }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Search, null); Spacer(Modifier.width(8.dp)); Text("جستجوی کانفیگ‌های عمومی")
                        }
                    }
                }
                Spacer(Modifier.weight(1f))
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
    val protocol = raw.substringBefore("://", "").lowercase()
    val endpoint = Regex("@([^@:/?#]+):\\d+").find(raw)?.groupValues?.get(1)
        ?: Regex("^([a-zA-Z0-9.-]+):\\d+").find(raw.substringAfter("://", ""))?.groupValues?.get(1)
        ?: "آدرس مخفی"
    return Server("سرور " + (index + 1), endpoint, protocol, raw)
}
