package dev.busung.s25uroot

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** All commands have constant arguments; user text is never executed by the shell. */
internal data class DiagnosticProbe(
    val id: String,
    val description: String,
    val command: List<String>,
)

internal enum class ProbeOutcome { OK, UNAVAILABLE, TIMED_OUT, FAILED }

internal data class DiagnosticObservation(
    val id: String,
    val description: String,
    val outcome: ProbeOutcome,
    val output: String,
    val detail: String = "",
)

internal data class InvestigationReport(
    val createdAt: String,
    val transport: String,
    val device: Map<String, String>,
    val observations: List<DiagnosticObservation>,
    val firmware: FirmwareInspection? = null,
) {
    fun asJson(): String {
        val deviceJson = JSONObject()
        device.forEach { (key, value) -> deviceJson.put(key, value) }
        val entries = JSONArray()
        observations.forEach {
            entries.put(JSONObject()
                .put("id", it.id)
                .put("description", it.description)
                .put("outcome", it.outcome.name)
                .put("output", it.output)
                .put("detail", it.detail))
        }
        val result = JSONObject()
            .put("schemaVersion", 1)
            .put("createdAt", createdAt)
            .put("transport", transport)
            .put("device", deviceJson)
            .put("observations", entries)
            .put("limits", JSONArray().apply {
                put("Wireless ADB through Shizuku gives shell privileges, not root.")
                put("Boot and vendor partitions are not readable through stock shell access.")
                put("Matching a kernel version does not verify exploit compatibility.")
            })
        firmware?.let {
            result.put("importedFirmware", JSONObject()
                .put("name", it.name)
                .put("sizeBytes", it.sizeBytes)
                .put("sha256", it.sha256)
                .put("format", it.format)
                .put("bootHeaderVersion", it.bootHeaderVersion ?: JSONObject.NULL))
        }
        return result.toString(2)
    }
}

/**
 * Read-only research probes. No root payload is invoked, no partition block
 * devices are opened, and no network/upload action exists in this collector.
 */
internal object InvestigationCollector {
    private const val MAX_OUTPUT_BYTES = 16 * 1024
    private const val COMMAND_TIMEOUT_MS = 8_000L

    private val firmwareProperties = listOf(
        "ro.product.model",
        "ro.product.device",
        "ro.product.name",
        "ro.build.display.id",
        "ro.build.fingerprint",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.boot.bootloader",
        "gsm.version.baseband",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.product.cpu.abi",
    )

    val probes: List<DiagnosticProbe> = buildList {
        add(DiagnosticProbe("identity.uid", "Authorized Shizuku process UID",
            listOf("/system/bin/id", "-u")))
        firmwareProperties.forEach { name ->
            add(DiagnosticProbe(name, "Firmware property: " + name,
                listOf("/system/bin/getprop", name)))
        }
        add(DiagnosticProbe("kernel.uname", "Kernel release and build",
            listOf("/system/bin/uname", "-a")))
        add(DiagnosticProbe("kernel.proc_version", "Kernel /proc/version",
            listOf("/system/bin/cat", "/proc/version")))
        add(DiagnosticProbe("kernel.config", "Kernel config flag availability",
            listOf("/system/bin/sh", "-c", """
                if [ -r /proc/config.gz ]; then
                    zcat /proc/config.gz 2>/dev/null | grep -E '^(CONFIG_(MODULES|MODVERSIONS|MODULE_SIG|MODULE_FORCE_LOAD|KALLSYMS|KALLSYMS_ALL|IKCONFIG|IKCONFIG_PROC|DEBUG_INFO_BTF|KPROBES|FTRACE|TRACEPOINTS|SECURITY_SELINUX|ARM64|RT_MUTEXES|FUTEX))='
                else
                    echo 'Unavailable: /proc/config.gz; obtain the matching Samsung kernel configuration offline'
                fi
            """.trimIndent())))
        add(DiagnosticProbe("kernel.modules", "Loaded kernel modules",
            listOf("/system/bin/cat", "/proc/modules")))
        add(DiagnosticProbe("kernel.trace_event", "sched_blocked_reason trace event ID",
            listOf("/system/bin/sh", "-c", """
                if [ -r /sys/kernel/tracing/events/sched/sched_blocked_reason/id ]; then
                    cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id
                elif [ -r /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id ]; then
                    cat /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id
                else
                    echo 'Unavailable: tracefs event ID is not readable to ADB shell'
                fi
            """.trimIndent())))
        add(DiagnosticProbe("kernel.kallsyms", "Kernel symbols access (no addresses exported)",
            listOf("/system/bin/sh", "-c", """
                if [ -r /proc/kallsyms ]; then
                    echo 'Readable: /proc/kallsyms (contents deliberately not collected)'
                else
                    echo 'Unavailable: /proc/kallsyms'
                fi
            """.trimIndent())))
        add(DiagnosticProbe("storage.partitions", "Partition names and public sizes only",
            listOf("/system/bin/cat", "/proc/partitions")))
        add(DiagnosticProbe("security.selinux", "SELinux enforcement",
            listOf("/system/bin/getenforce")))
        add(DiagnosticProbe("boot.slot", "Active boot slot if set",
            listOf("/system/bin/getprop", "ro.boot.slot_suffix")))
    }

    fun snapshot(): Map<String, String> {
        val snapshot = DeviceSnapshot.current()
        return linkedMapOf(
            "manufacturer" to snapshot.manufacturer,
            "model" to snapshot.model,
            "device" to snapshot.device,
            "displayBuild" to snapshot.buildId,
            "buildFingerprint" to snapshot.fingerprint,
            "kernelRelease" to snapshot.kernelRelease,
            "kernelVersionInfo" to snapshot.kernelVersionInfo,
            "machine" to snapshot.machine,
            "androidRelease" to snapshot.androidRelease,
            "sdk" to snapshot.sdk.toString(),
            "abi" to snapshot.abi,
            "pageSize" to snapshot.pageSize.toString(),
        )
    }

    suspend fun collect(
        useShizuku: Boolean,
        progress: (Int, Int, String) -> Unit = { _, _, _ -> },
    ): InvestigationReport {
        if (useShizuku) {
            check(ShizukuController.isGranted()) {
                "Shizuku must be running and authorized before shell diagnostics"
            }
        }
        val observations = mutableListOf<DiagnosticObservation>()
        if (useShizuku) {
            probes.forEachIndexed { index, probe ->
                progress(index + 1, probes.size, probe.description)
                observations += capture(probe)
            }
        }
        return InvestigationReport(
            createdAt = Instant.now().toString(),
            transport = if (useShizuku) "SHIZUKU_ADB_SHELL" else "APP_ONLY",
            device = snapshot(),
            observations = observations,
        )
    }

    private suspend fun capture(probe: DiagnosticProbe): DiagnosticObservation =
        withContext(Dispatchers.IO) {
            var process: Process? = null
            val readers = Executors.newFixedThreadPool(2) { task ->
                Thread(task, "investigation-probe-reader").apply { isDaemon = true }
            }
            try {
                val current = ShizukuController.exec(probe.command.toTypedArray())
                process = current
                val outFuture = readers.submit<String> { readLimited(current.inputStream) }
                val errFuture = readers.submit<String> { readLimited(current.errorStream) }
                val finished = current.waitFor(COMMAND_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                if (!finished) current.destroyForcibly()
                val stdout = runCatching {
                    outFuture.get(1500, TimeUnit.MILLISECONDS)
                }.getOrDefault("").trim()
                val stderr = runCatching {
                    errFuture.get(1500, TimeUnit.MILLISECONDS)
                }.getOrDefault("").trim()
                val code = if (finished) runCatching { current.exitValue() }.getOrDefault(-1) else -1
                val outcome = when {
                    !finished -> ProbeOutcome.TIMED_OUT
                    code == 0 && !stdout.startsWith("Unavailable:") -> ProbeOutcome.OK
                    code == 0 || stderr.contains("Permission denied", ignoreCase = true) ->
                        ProbeOutcome.UNAVAILABLE
                    else -> ProbeOutcome.FAILED
                }
                DiagnosticObservation(
                    id = probe.id,
                    description = probe.description,
                    outcome = outcome,
                    output = stdout,
                    detail = if (!finished) "Command timed out" else stderr.take(512),
                )
            } catch (exception: Exception) {
                DiagnosticObservation(
                    id = probe.id,
                    description = probe.description,
                    outcome = ProbeOutcome.FAILED,
                    output = "",
                    detail = exception.javaClass.simpleName + ": " +
                        (exception.message ?: "Unknown error"),
                )
            } finally {
                process?.let { runCatching { it.destroy() } }
                readers.shutdownNow()
            }
        }

    private fun readLimited(stream: InputStream): String {
        val buffer = ByteArray(4096)
        val output = ByteArrayOutputStream()
        stream.use { input ->
            while (true) {
                val read = input.read(buffer)
                if (read == -1) break
                val available = MAX_OUTPUT_BYTES - output.size()
                if (available > 0) output.write(buffer, 0, minOf(read, available))
            }
        }
        return output.toString(Charsets.UTF_8.name()) +
            if (output.size() == MAX_OUTPUT_BYTES) "\n[output capped at 16 KiB]" else ""
    }
}
