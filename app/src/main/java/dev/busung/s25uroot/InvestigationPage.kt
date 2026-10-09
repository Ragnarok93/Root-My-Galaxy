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
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
internal fun InvestigationPage(padding: PaddingValues) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var shizukuRunning by remember { mutableStateOf(false) }
    var shizukuGranted by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    val session: InvestigationSession = viewModel()
    var status by session.status
    var report by session.report
    var imported by session.imported
    var selectedSources by session.selectedSources
    var pendingBootSource by session.pendingBootSource
    val extracting by session.extracting
    val extractionStatus by session.extractionStatus
    val extractionResult by session.extractionResult
    var kernelConfig by session.kernelConfig
    var expanded by remember { mutableStateOf<String?>(null) }
    var expandedPackage by remember { mutableStateOf<String?>(null) }
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
                    val current = report ?: InvestigationReport(java.time.Instant.now().toString(), "APP_ONLY", InvestigationCollector.snapshot(), emptyList())
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri)?.use {
                            it.write(current.copy(firmwarePackages = imported).asJson().toByteArray(Charsets.UTF_8))
                        } ?: kotlin.error("Cannot open the destination document")
                    }
                }.onSuccess {
                    status = "Report exported locally"
                }.onFailure { exception ->
                    error = exception.message ?: "Could not export report"
                }
            }
        }
    }

    val kernelConfigExporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/gzip"),
    ) { uri ->
        if (uri != null) {
            scope.launch {
                runCatching {
                    val current = checkNotNull(kernelConfig) { "No extracted kernel config available" }
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri)?.use { out ->
                            out.write(current.bytes)
                        } ?: kotlin.error("Unable to open kernel config destination")
                    }
                }.onSuccess { status = "Kernel config exported" }
                    .onFailure { error = it.message ?: "Config export failed" }
            }
        }
    }

    val firmwarePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris ->
        if (uris.isNotEmpty()) scope.launch {
            busy = true
            error = null
            var count = 0
            val failures = mutableListOf<String>()
            val updated = imported.toMutableList()
            uris.take(12).forEachIndexed { index, uri ->
                status = "Inspecting package " + (index + 1) + "/" + minOf(uris.size, 12)
                runCatching { FirmwareInspector.inspect(context, uri) }
                    .onSuccess {
                        updated.removeAll { current -> current.name == it.name }
                        updated.add(it)
                        imported = updated.toList()
                        selectedSources = selectedSources + (it.name to uri)
                        count++
                    }
                    .onFailure { failures += (it.message ?: "Unable to inspect file") }
            }
            if (uris.size > 12) failures += "Limit of 12 files per selection."
            if (failures.isNotEmpty()) error = failures.take(3).joinToString("\n")
            status = "Indexed $count firmware package(s)"
            busy = false
        }
    }

    val bootExporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { destination ->
        val source = pendingBootSource
        pendingBootSource = null
        if (destination != null && source != null) {
            val selectedName = selectedSources.entries.firstOrNull { it.value == source }?.key
                ?: "firmware-package"
            session.extractBoot(context, source, selectedName, destination)
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
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
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
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = !busy,
                            onClick = {
                                scope.launch {
                                    busy = true
                                    error = null
                                    runCatching {
                                        InvestigationCollector.collect(useShizuku = false)
                                    }.onSuccess {
                                        report = it.copy(firmwarePackages = imported)
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
                                        report = it.copy(firmwarePackages = imported)
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
                    Text("Extract accessible kernel config", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "If /proc/config.gz is accessible to the authorized Shizuku shell, " +
                            "capture the original gzip bytes and save them with Android's document picker. " +
                            "This is not a firmware partition dump and will fail safely when access is blocked.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(
                        enabled = shizukuRunning && shizukuGranted && !busy,
                        onClick = {
                            scope.launch {
                                busy = true
                                error = null
                                status = "Reading exposed kernel configuration"
                                runCatching { KernelConfigReader.read() }
                                    .onSuccess {
                                        kernelConfig = it
                                        status = "Kernel config captured (not saved yet)"
                                    }
                                    .onFailure {
                                        error = it.message ?: "Kernel config unavailable"
                                        status = "Kernel config unavailable under ADB-shell permissions"
                                    }
                                busy = false
                            }
                        },
                    ) { Text("Read config.gz") }
                    kernelConfig?.let { config ->
                        Text(
                            config.sizeBytes.toString() + " bytes\nSHA-256: " + config.sha256,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        OutlinedButton(
                            enabled = !busy,
                            onClick = { kernelConfigExporter.launch("S20plus-kernel-config.gz") },
                        ) { Text("Save config.gz") }
                    }
                }
            }
        }

        item {
            Card {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Firmware package analysis", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Select AP, BL, CP, CSC or HOME_CSC TAR.MD5 files directly, or a Samsung " +
                            "firmware ZIP. Indexed partition names, sizes, offsets and formats are " +
                            "shown without extracting or decompressing the firmware.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(enabled = !busy && !extracting, onClick = { firmwarePicker.launch(arrayOf("*/*")) }) {
                        Text("Select firmware packages")
                    }
                    if (imported.isNotEmpty()) {
                        Text(
                            imported.size.toString() + " packages · " +
                                imported.sumOf { it.entries.size } + " entries",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        OutlinedButton(
                            enabled = !busy && !extracting,
                            onClick = { reportExporter.launch("RootMyGalaxy-firmware-inventory.json") },
                        ) { Text("Export inventory JSON") }
                        OutlinedButton(
                            enabled = !busy && !extracting,
                            onClick = {
                                imported = emptyList()
                                selectedSources = emptyMap()
                                expandedPackage = null
                            },
                        ) { Text("Clear packages") }
                    }
                    if (extracting) {
                        CircularProgressIndicator()
                        Text(extractionStatus, style = MaterialTheme.typography.bodySmall)
                        OutlinedButton(onClick = session::cancelBootExtraction) {
                            Text("Cancel boot extraction")
                        }
                    } else if (extractionStatus.isNotBlank()) {
                        Text(extractionStatus, style = MaterialTheme.typography.bodySmall)
                    }
                    extractionResult?.let { extracted ->
                        Text(
                            "Extracted: " + extracted.sourceEntry + "\n" +
                                extracted.sizeBytes + " bytes\nSHA-256: " + extracted.sha256,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Text(
                        "Read-only local-file access. Cloud document providers may require a " +
                            "local copy for random access. ZIP contents are listed but nested TAR " +
                            "packages require selecting the TAR directly.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        imported.forEach { pkg ->
            item(key = "package-" + pkg.name) {
                Card {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(pkg.name, style = MaterialTheme.typography.titleMedium)
                        Text(
                            pkg.packageRole + " · " + pkg.format + " · " +
                                pkg.entries.size + " files · " + pkg.sizeBytes + " bytes",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Text(
                            "SHA-256: " + (pkg.sha256 ?: "Not calculated (over 32 MiB)"),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        pkg.bootHeaderVersion?.let { Text("Boot header: v$it") }
                        pkg.warnings.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                        if ((pkg.packageRole == "AP" ||
                                pkg.format.startsWith("ZIP")) &&
                            selectedSources.containsKey(pkg.name)
                        ) {
                            Button(
                                enabled = !busy && !extracting,
                                onClick = {
                                    pendingBootSource = selectedSources[pkg.name]
                                    bootExporter.launch("boot.img.lz4")
                                },
                            ) { Text("Extract boot.img.lz4") }
                        }
                        if (pkg.entries.isNotEmpty()) {
                            OutlinedButton(onClick = {
                                expandedPackage = if (expandedPackage == pkg.name) null else pkg.name
                            }) {
                                Text(if (expandedPackage == pkg.name) "Hide partitions" else "Show partitions")
                            }
                        }
                    }
                }
            }
            if (expandedPackage == pkg.name) {
                items(pkg.entries, key = { "entry-" + pkg.name + "-" + it.path }) { entry ->
                    Card {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text(entry.path, style = MaterialTheme.typography.titleSmall)
                            Text(
                                entry.category + " · " + entry.format + " · " + entry.sizeBytes + " bytes",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            entry.compressedBytes?.let { Text("Compressed: $it bytes", style = MaterialTheme.typography.bodySmall) }
                            entry.payloadOffset?.let { Text("TAR data offset: $it", style = MaterialTheme.typography.bodySmall) }
                            Text(
                                entry.note,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
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
