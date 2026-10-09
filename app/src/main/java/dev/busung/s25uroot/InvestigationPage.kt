package dev.busung.s25uroot

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun InvestigationPage(padding: PaddingValues) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var shizukuRunning by remember { mutableStateOf(false) }
    var shizukuGranted by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Not yet collected") }
    var report by remember { mutableStateOf<InvestigationReport?>(null) }
    var imported by remember { mutableStateOf<FirmwareInspection?>(null) }
    var expanded by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    val refreshConnection = {
        shizukuRunning = ShizukuController.isRunning()
        shizukuGranted = ShizukuController.isGranted()
    }

    val reportExporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri != null) {
            scope.launch {
                runCatching {
                    val current = checkNotNull(report) { "No investigation report available" }
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri)?.use {
                            it.write(current.copy(firmware = imported).asJson().toByteArray(Charsets.UTF_8))
                        } ?: error("Cannot open the destination document")
                    }
                }.onSuccess {
                    status = "Report exported locally"
                }.onFailure { exception ->
                    error = exception.message ?: "Could not export report"
                }
            }
        }
    }

    val firmwarePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            scope.launch {
                busy = true
                error = null
                status = "Inspecting selected firmware file"
                runCatching { FirmwareInspector.inspect(context, uri) }
                    .onSuccess {
                        imported = it
                        status = "Firmware file inspected locally"
                    }
                    .onFailure { exception ->
                        error = exception.message ?: "Could not inspect file"
                    }
                busy = false
            }
        }
    }

    LaunchedEffect(Unit) {
        ShizukuController.pingUntilRunning()
        refreshConnection()
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Investigation", style = MaterialTheme.typography.headlineLarge)
                Text(
                    "Galaxy S20+ kernel 4.19 research workspace",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        item {
            Card {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text("Wireless ADB through Shizuku", style = MaterialTheme.typography.titleMedium)
                    Text(
                        if (!shizukuRunning) "Service not connected"
                        else if (!shizukuGranted) "Service running — authorization required"
                        else "Service running — authorized",
                    )
                    Text(
                        "1. Open Developer options and enable Wireless debugging. " +
                            "2. In Shizuku, pair with the Android pairing code and start the service. " +
                            "3. Return here, refresh and authorize this app. After reboot, restart Shizuku.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        OutlinedButton(onClick = {
                            runCatching {
                                context.startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
                            }.onFailure { Toast.makeText(context, "Open Developer options in Settings", Toast.LENGTH_LONG).show() }
                        }) { Text("Developer options") }
                        OutlinedButton(onClick = {
                            val launch = context.packageManager
                                .getLaunchIntentForPackage("moe.shizuku.manager")
                            val intent = launch ?: Intent(
                                Intent.ACTION_VIEW, Uri.parse("https://shizuku.rikka.app/guide/setup/"),
                            )
                            context.startActivity(intent)
                        }) { Text("Shizuku") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = refreshConnection) {
                            Text("Refresh")
                        }
                        Button(
                            enabled = shizukuRunning && !shizukuGranted && !busy,
                            onClick = {
                                scope.launch {
                                    error = null
                                    runCatching { ShizukuController.requestPermission() }
                                        .onFailure { error = it.message ?: "Shizuku authorization failed" }
                                    refreshConnection()
                                }
                            },
                        ) { Text("Authorize") }
                    }
                    Text(
                        "Shizuku uses authorized ADB-shell privileges, not root. " +
                            "Wireless debugging does not grant access to protected firmware partitions.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        item {
            Card {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text("Collect evidence", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Read-only probes: firmware fingerprint, build/bootloader/baseband, " +
                            "kernel version, module and config availability, SELinux, " +
                            "trace event ID, and partition names. No raw partitions are read.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    if (busy) CircularProgressIndicator()
                    Text(status, style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !busy,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    error = null
                                    runCatching {
                                        InvestigationCollector.collect(useShizuku = false)
                                    }.onSuccess {
                                        report = it.copy(firmware = imported)
                                        status = "App-only snapshot complete"
                                    }.onFailure { error = it.message }
                                    busy = false
                                }
                            },
                        ) { Text("App snapshot") }
                        Button(
                            enabled = shizukuRunning && shizukuGranted && !busy,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    error = null
                                    runCatching {
                                        InvestigationCollector.collect(useShizuku = true) { index, total, label ->
                                            scope.launch { status = "Probe " + index + "/" + total + ": " + label }
                                        }
                                    }.onSuccess {
                                        report = it.copy(firmware = imported)
                                        status = "Shizuku diagnostics complete"
                                    }.onFailure { error = it.message ?: "Collection failed" }
                                    busy = false
                                }
                            },
                        ) { Text("Collect via Shizuku") }
                    }
                }
            }
        }

        item {
            Card {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text("Offline firmware analysis", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Select a previously obtained boot.img or boot.img.lz4 to identify its " +
                            "format, boot header version and SHA-256. The app cannot extract the " +
                            "full Samsung AP archive or read protected partitions using shell access.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedButton(
                        enabled = !busy,
                        onClick = { firmwarePicker.launch(arrayOf("*/*")) },
                    ) { Text("Inspect firmware file") }
                    imported?.let {
                        Text(
                            it.name + "\n" + it.format + "\n" + it.sizeBytes +
                                " bytes\nSHA-256: " + it.sha256 +
                                (it.bootHeaderVersion?.let { version -> "\nBoot header: v" + version } ?: ""),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }

        if (error != null) {
            item {
                Text(
                    error.orEmpty(),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        report?.let { current ->
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Report", style = MaterialTheme.typography.titleMedium)
                    Text(
                        current.transport + " · " + current.observations.size + " probes",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(
                        enabled = !busy,
                        onClick = { reportExporter.launch("RootMyGalaxy-S20plus-investigation.json") },
                    ) { Text("Export JSON") }
                    Text(
                        "Stored only in this screen until exported. Review before sharing; " +
                            "device firmware identifiers may be included. Nothing is uploaded automatically.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            items(current.observations, key = { it.id }) { observation ->
                Card {
                    Column(
                        modifier = Modifier.fillMaxWidth()
                            .clickable {
                                expanded = if (expanded == observation.id) null else observation.id
                            }
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(observation.description, style = MaterialTheme.typography.titleSmall)
                        Text(
                            observation.outcome.name + " · " + observation.id,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (expanded == observation.id) {
                            HorizontalDivider()
                            Text(
                                observation.output.ifBlank { observation.detail.ifBlank { "No output" } },
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                            )
                            if (observation.detail.isNotBlank() && observation.output.isNotBlank()) {
                                Text(observation.detail, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        }
    }
}
