package dev.busung.s25uroot

import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** A deliberately read-only allowlist of device-side investigations. */
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
        val fields = JSONObject()
        device.forEach { (key, value) -> fields.put(key, value) }
        val entries = JSONArray()
        observations.forEach { observation ->
            entries.put(JSONObject()
                .put("id", observation.id)
                .put("description", observation.description)
                .put("outcome", observation.outcome.name)
                .put("output", observation.output)
                .put("detail", observation.detail))
        }
        val result = JSONObject()
            .put("schemaVersion", 1)
            .put("createdAt", createdAt)
            .put("transport", transport)
            .put("device", fields)
            .put("observations", entries)
            .put("limits", JSONArray().apply {
                put("Shizuku started through wireless debugging has ADB shell privileges, not root.")
                put("Raw boot/vendor partitions and complete Samsung AP firmware are not shell-readable on locked stock firmware.")
                put("A kernel version match does not establish exploit compatibility.")
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
 * No arbitrary command input, shell scripting supplied by users, partition writes,
 * root requests, or automatic uploading. Only whitelisted properties and read-only
 * diagnostic files are collected. Failures are preserved rather than hidden.
 */
internal object InvestigationCollector {
    private const val COMMAND_TIMEOUT_MS = 8_000L
    private const val MAX_OUTPUT_BYTES = 16 * 1024

    private val propertyNames = listOf(
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
        add(DiagnosticProbe("identity.uid", "Shizuku process UID", listOf("/system/bin/id", "-u")))
        propertyNames.forEach { name ->
            add(DiagnosticProbe(name, "Firmware property: " + name,
                listOf("/system/bin/getprop", name)))
        }
        add(DiagnosticProbe("kernel.uname", "Kernel release and build",
            listOf("/system/bin/uname", "-a")))
        add(DiagnosticProbe("kernel.proc_version", "Kernel /proc/version",
            listOf("/system/bin/cat", "/proc/version")))
        add(DiagnosticProbe("kernel.config", "Read-only kernel configuration flags",
            listOf("/system/bin/sh", "-c", """
                if [ -r /proc/config.gz ]; then
                    zcat /proc/config.gz 2>/dev/null | grep -E '^(CONFIG_(MODULES|MODVERSIONS|MODULE_SIG|MODULE_FORCE_LOAD|KALLSYMS|KALLSYMS_ALL|IKCONFIG|IKCONFIG_PROC|DEBUG_INFO_BTF|KPROBES|FTRACE|TRACEPOINTS|SECURITY_SELINUX|SECURITY_DEFEX|ARM64|RT_MUTEXES|FUTEX|RKP|KDP))='
                else
                    echo 'Unavailable: /proc/config.gz (obtain exact kernel config from Samsung sources)'
                fi
            """.trimIndent())))
        add(DiagnosticProbe("kernel.modules", "Loaded kernel module names",
            listOf("/system/bin/cat", "/proc/modules")))
        add(DiagnosticProbe("kernel.trace_event", "sched_blocked_reason event ID",
            listOf("/system/bin/sh", "-c", """
                for f in /sys/kernel/tracing/events/sched/sched_blocked_reason/id /sys/kernel/debug/tracing/events/sched/sched_blocked_reason/id; do
                    if [ -r "$f" ]; then cat "$f"; exit; fi
                done
                echo 'Unavailable: tracefs event ID is not readable by shell'
            """.trimIndent())))
        add(DiagnosticProbe("kernel.kallsyms", "Kernel symbols readability (no addresses collected)",
            listOf("/system/bin/sh", "-c", """
                if [ -r /proc/kallsyms ]; then echo 'Readable: /proc/kallsyms; symbols NOT exported by this diagnostic'; else echo 'Unavailable: /proc/kallsyms'; fi
            """.trimIndent())))
        add(DiagnosticProbe("storage.partitions", "Partition names and public sizes (no content)",
            listOf("/system/bin/cat", "/proc/partitions")))
        add(DiagnosticProbe("security.selinux", "Current SELinux enforcement mode",
            listOf("/system/bin/getenforce")))
        add(DiagnosticProbe("boot.slot", "Active boot slot if available",
            listOf("/system/bin/getprop", "ro.boot.slot_suffix")))
    }

    fun snapshot(): Map<String, String> {
        val device = DeviceSnapshot.current()
        return linkedMapOf(
            "manufacturer" to device.manufacturer,
            "model" to device.model,
            "device" to device.device,
            "displayBuild" to device.buildId,
            "buildFingerprint" to device.fingerprint,
            "kernelRelease" to device.kernelRelease,
            "kernelVersionInfo" to device.kernelVersionInfo,
            "architecture" to device.machine,
            "androidRelease" to device.androidRelease,
            "sdk" to device.sdk.toString(),
            "abi" to device.abi,
            "pageSize" to device.pageSize.toString(),
            "expectedStudyTarget" to "SM-G986U1 / Snapdragon 865 / kernel 4.19.113",
        )
    }

    suspend fun collect(
        useShizuku: Boolean,
        progress: (Int, Int, String) -> Unit = { _, _, _ -> },
    ): InvestigationReport {
        if (useShizuku) {
            check(ShizukuController.isGranted()) {
                "Shizuku must be running and permission granted before collecting shell diagnostics"
            }
        }
        val gathered = mutableListOf<DiagnosticObservation>()
        if (useShizuku) {
            probes.forEachIndexed { index, probe ->
                progress(index + 1, probes.size, probe.description)
                gathered += capture(probe)
            }
        }
        return InvestigationReport(
            createdAt = Instant.now().toString(),
            transport = if (useShizuku) "SHIZUKU_ADB_SHELL" else "APP_ONLY",
            device = snapshot(),
            observations = gathered,
        )
    }

    private suspend fun capture(probe: DiagnosticProbe): DiagnosticObservation =
        withContext(Dispatchers.IO) {
            var process: Process? = null
            // Read stdout and stderr concurrently to prevent OS pipe-buffer deadlocks.
            // Executor futures have bounded waits even if the remote process ignores termination.
            val readers = Executors.newFixedThreadPool(2) { runnable ->
                Thread(runnable, "investigation-probe-reader").apply { isDaemon = true }
            }
            try {
                val current = ShizukuController.exec(probe.command.toTypedArray())
                process = current
                val stdout = readers.submit<String> { limitedText(current.inputStream) }
                val stderr = readers.submit<String> { limitedText(current.errorStream) }
                val finished = current.waitFor(COMMAND_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                if (!finished) current.destroyForcibly()
                val out = runCatching { stdout.get(1500, TimeUnit.MILLISECONDS) }.getOrDefault("").trim()
                val err = runCatching { stderr.get(1500, TimeUnit.MILLISECONDS) }.getOrDefault("").trim()
                val code = if (finished) runCatching { current.exitValue() }.getOrDefault(-1) else -1
                val outcome = when {
                    !finished -> ProbeOutcome.TIMED_OUT
                    code == 0 && !out.startsWith("Unavailable:") -> ProbeOutcome.OK
                    code == 0 || err.contains("Permission denied", ignoreCase = true) ->
                        ProbeOutcome.UNAVAILABLE
                    else -> ProbeOutcome.FAILED
                }
                DiagnosticObservation(
                    id = probe.id, description = probe.description, outcome = outcome,
                    output = out, detail = if (!finished) "Command timed out" else err.take(512),
                )
            } catch (exception: Exception) {
                DiagnosticObservation(
                    probe.id, probe.description, ProbeOutcome.FAILED, "",
                    exception.javaClass.simpleName + ": " + (exception.message ?: "Unknown failure"),
                )
            } finally {
                process?.let { runCatching { it.destroy() } }
                readers.shutdownNow()
            }
        }

    private fun limitedText(input: InputStream): String {
        val buffer = ByteArray(4096)
        val collected = ByteArrayOutputStream()
        input.use { stream ->
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                val remaining = MAX_OUTPUT_BYTES - collected.size()
                if (remaining > 0) collected.write(buffer, 0, minOf(read, remaining))
            }
        }
        return collected.toString(Charsets.UTF_8.name()) +
            if (collected.size() == MAX_OUTPUT_BYTES) "\n[output capped at 16 KiB]" else ""
    }
}
