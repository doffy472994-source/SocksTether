package dev.itsricky.sockstether

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val dark = isSystemInDarkTheme()
            val ctx = LocalContext.current
            val scheme = when {
                Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
                dark -> darkColorScheme()
                else -> lightColorScheme()
            }
            MaterialTheme(colorScheme = scheme) {
                Surface(Modifier.safeDrawingPadding()) { MainScreen() }
            }
        }
    }
}

private fun startTether(ctx: Context) =
    ContextCompat.startForegroundService(ctx, Intent(ctx, TetherService::class.java).setAction(TetherService.ACTION_START))

private fun stopTether(ctx: Context) =
    ctx.startService(Intent(ctx, TetherService::class.java).setAction(TetherService.ACTION_STOP))

private fun fmtBytes(b: Long): String = when {
    b >= 1L shl 30 -> "%.2f GB".format(b / (1L shl 30).toDouble())
    b >= 1L shl 20 -> "%.1f MB".format(b / (1L shl 20).toDouble())
    b >= 1L shl 10 -> "%.0f KB".format(b / 1024.0)
    else -> "$b B"
}

@Composable
private fun Section(title: String, content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@Composable
private fun SwitchRow(label: String, hint: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label)
            Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

@Composable
private fun MainScreen() {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val store = remember { ConfigStore(ctx) }
    var cfg by remember { mutableStateOf(store.load()) }
    fun update(c: Config) { cfg = c; store.save(c) }

    val running by TetherState.running.collectAsState()
    val hotspot by TetherState.hotspot.collectAsState()
    val log by TetherState.logLines.collectAsState()
    var addrs by remember { mutableStateOf(emptyList<LocalAddress>()) }
    var stats by remember { mutableStateOf(Stats()) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        while (true) {
            addrs = withContext(Dispatchers.IO) { NetInfo.localAddresses() }
            stats = TetherState.stats()
            delay(1000)
        }
    }

    val permissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        startTether(ctx) // the hotspot reports its own error if its permission was refused
    }

    fun onToggle() {
        if (running) { stopTether(ctx); return }
        error = when {
            cfg.port !in 1024..65535 -> "Port must be between 1024 and 65535."
            !cfg.hotspot && cfg.auth && (cfg.user.isBlank() || cfg.pass.isBlank()) -> "Username and password can't be empty while authentication is on."
            cfg.hotspot && !ConfigStore.validHotspotName(cfg.hotspotName) -> "Network name: 1–22 letters, digits, - or _."
            cfg.hotspot && !ConfigStore.validHotspotPass(cfg.hotspotPass) -> "Wi-Fi password must be 8–63 characters."
            else -> null
        }
        if (error != null) return
        val wanted = buildList {
            if (Build.VERSION.SDK_INT >= 33) {
                add(Manifest.permission.POST_NOTIFICATIONS)
                if (cfg.hotspot) add(Manifest.permission.NEARBY_WIFI_DEVICES)
            } else if (cfg.hotspot) add(Manifest.permission.ACCESS_FINE_LOCATION)
        }.filter { ContextCompat.checkSelfPermission(ctx, it) != PackageManager.PERMISSION_GRANTED }
        if (wanted.isEmpty()) startTether(ctx) else permissions.launch(wanted.toTypedArray())
    }

    Column(
        Modifier.verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("SocksTether", style = MaterialTheme.typography.headlineMedium)

        Button(
            onClick = ::onToggle,
            modifier = Modifier.fillMaxWidth(),
            colors = if (running) ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error) else ButtonDefaults.buttonColors(),
        ) { Text(if (running) "Stop" else "Start", fontSize = 18.sp) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

        if (running) {
            when (val h = hotspot) {
                is HotspotStatus.On -> Section("Hotspot") {
                    Text("Join this network on the other device, or scan the code.")
                    Image(Qr.wifi(h.ssid, h.password).asImageBitmap(), "Wi-Fi QR code", Modifier.size(200.dp).align(Alignment.CenterHorizontally))
                    Text("Network: ${h.ssid}", fontFamily = FontFamily.Monospace)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Password: ${h.password}", fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
                        TextButton({ clipboard.setText(AnnotatedString(h.password)) }) { Text("Copy") }
                    }
                }
                HotspotStatus.Starting -> Section("Hotspot") { Text("Starting…") }
                is HotspotStatus.Failed -> Section("Hotspot") { Text(h.reason, color = MaterialTheme.colorScheme.error) }
                HotspotStatus.Off -> {}
            }

            Section("Proxy") {
                val shown = addrs.filter { it.clientFacing }.ifEmpty { addrs }
                if (shown.isEmpty()) Text("No local address yet. Waiting for the hotspot…")
                shown.forEach { a ->
                    val url = buildString {
                        append("socks5://")
                        cfg.proxyCredentials()?.let { (u, p) -> append(Uri.encode(u)).append(':').append(Uri.encode(p)).append('@') }
                        append(a.ip).append(':').append(cfg.port)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("${a.ip}:${cfg.port}", fontFamily = FontFamily.Monospace)
                            Text(a.iface, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton({ clipboard.setText(AnnotatedString(url)) }) { Text("Copy URL") }
                    }
                }
                Text(
                    "${stats.connections} active · ↑ ${fmtBytes(stats.up)} · ↓ ${fmtBytes(stats.down)}",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        Section("Settings") {
            OutlinedTextField(
                value = if (cfg.port == 0) "" else cfg.port.toString(),
                onValueChange = { update(cfg.copy(port = it.filter(Char::isDigit).take(5).toIntOrNull() ?: 0)) },
                label = { Text("Port") }, singleLine = true, enabled = !running,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            if (!cfg.hotspot) SwitchRow("Require login", "Username and password (SOCKS5 auth)", cfg.auth, !running) { update(cfg.copy(auth = it)) }
            if (!cfg.hotspot && cfg.auth) {
                OutlinedTextField(
                    value = cfg.user, onValueChange = { update(cfg.copy(user = it.trim())) },
                    label = { Text("Username") }, singleLine = true, enabled = !running, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = cfg.pass, onValueChange = { update(cfg.copy(pass = it.trim())) },
                    label = { Text("Password") }, singleLine = true, enabled = !running, modifier = Modifier.fillMaxWidth(),
                )
                TextButton({ update(cfg.copy(pass = ConfigStore.randomPassword())) }, enabled = !running) { Text("Generate new password") }
            }
            SwitchRow("Own Wi-Fi Direct network", "Create a private Wi-Fi network just for this proxy", cfg.hotspot, !running) { update(cfg.copy(hotspot = it)) }
            if (cfg.hotspot) {
                Text(
                    "Proxy login is automatic: user \"${Config.HOTSPOT_USER}\" + the Wi-Fi password below.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = cfg.hotspotName, onValueChange = { update(cfg.copy(hotspotName = it.trim().take(22))) },
                    label = { Text("Network name") }, prefix = { Text("DIRECT-ST-") },
                    singleLine = true, enabled = !running, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = cfg.hotspotPass, onValueChange = { update(cfg.copy(hotspotPass = it.trim().take(63))) },
                    label = { Text("Wi-Fi password (8+ characters)") }, singleLine = true, enabled = !running,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            SwitchRow("Force mobile data", "Send proxied traffic out over cellular", cfg.cellular, !running) { update(cfg.copy(cellular = it)) }
        }

        if (log.isNotEmpty()) Section("Log") {
            Text(log.takeLast(12).joinToString("\n"), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
    }
}
