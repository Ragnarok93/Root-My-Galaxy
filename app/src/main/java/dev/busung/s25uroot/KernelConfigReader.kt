package dev.busung.s25uroot

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal data class KernelConfigCapture(val bytes: ByteArray, val sha256: String) {
    val sizeBytes: Int get() = bytes.size
}

/**
 * Export of /proc/config.gz only if the running kernel exposes it to Shizuku.
 * The data are copied into app memory; never written to /dev/block or passed
 * to a shell command composed from user input.
 */
internal object KernelConfigReader {
    private const val MAX_CONFIG_BYTES = 3 * 1024 * 1024
    private const val READ_TIMEOUT_SECONDS = 6L

    suspend fun read(): KernelConfigCapture = withContext(Dispatchers.IO) {
        check(ShizukuController.isGranted()) { "Authorize Shizuku first" }
        val process = ShizukuController.exec(arrayOf("/system/bin/cat", "/proc/config.gz"))
        val reader = Executors.newSingleThreadExecutor { task ->
            Thread(task, "kernel-config-reader").apply { isDaemon = true }
        }
        try {
            val task = reader.submit<ByteArray> {
                val result = ByteArrayOutputStream()
                process.inputStream.use { input ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        check(result.size() + read <= MAX_CONFIG_BYTES) {
                            "config.gz exceeded 3 MiB; refusing to store it"
                        }
                        result.write(buffer, 0, read)
                    }
                }
                result.toByteArray()
            }
            val data = task.get(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            check(process.waitFor(2, TimeUnit.SECONDS) && process.exitValue() == 0) {
                "The kernel does not expose /proc/config.gz to ADB shell"
            }
            check(data.size >= 2 && data[0] == 0x1f.toByte() && data[1] == 0x8b.toByte()) {
                "The returned kernel config is not gzip data"
            }
            val sha = MessageDigest.getInstance("SHA-256")
                .digest(data).joinToString("") { "%02x".format(it) }
            KernelConfigCapture(data, sha)
        } finally {
            runCatching { process.destroy() }
            reader.shutdownNow()
        }
    }
}
