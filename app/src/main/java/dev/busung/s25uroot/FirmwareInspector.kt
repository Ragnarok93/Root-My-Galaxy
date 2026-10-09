package dev.busung.s25uroot

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SeekableByteChannel
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

internal data class FirmwareInspection(
    val name: String,
    val sizeBytes: Long,
    val sha256: String?,
    val format: String,
    val bootHeaderVersion: Int?,
    val packageRole: String = "Unknown",
    val entries: List<FirmwareArchiveEntry> = emptyList(),
    val warnings: List<String> = emptyList(),
    val truncated: Boolean = false,
)

/** Read-only user-selected SAF archive inspection; no extraction and no root. */
internal object FirmwareInspector {
    private const val MAX_FILE_NAME = 160
    private const val HASH_MAX_BYTES = 32L * 1024L * 1024L

    fun identify(firstBytes: ByteArray): Pair<String, Int?> {
        if (firstBytes.size >= 44 &&
            firstBytes.copyOfRange(0, 8).contentEquals("ANDROID!".toByteArray(Charsets.US_ASCII))) {
            val version = ByteBuffer.wrap(firstBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(40)
            return "Android boot image" to version
        }
        if (firstBytes.size >= 4 &&
            firstBytes[0] == 0x04.toByte() &&
            firstBytes[1] == 0x22.toByte() &&
            firstBytes[2] == 0x4d.toByte() &&
            firstBytes[3] == 0x18.toByte()) {
            return "LZ4-compressed image (no decompression)" to null
        }
        if (firstBytes.size >= 4 &&
            firstBytes[0] == 0x50.toByte() &&
            firstBytes[1] == 0x4b.toByte()) {
            return "ZIP archive" to null
        }
        if (firstBytes.size >= 262 &&
            firstBytes.copyOfRange(257, 262).contentEquals("ustar".toByteArray(Charsets.US_ASCII))) {
            return "TAR archive" to null
        }
        return "Unknown / raw binary" to null
    }

    suspend fun inspect(context: Context, uri: Uri): FirmwareInspection = withContext(Dispatchers.IO) {
        val filename = context.contentResolver.query(
            uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }?.take(MAX_FILE_NAME) ?: uri.lastPathSegment?.substringAfterLast('/')?.take(MAX_FILE_NAME)
            ?: "selected-firmware"

        context.contentResolver.openFileDescriptor(uri, "r")?.use { descriptor ->
            // Large archive indexing requires seekable file descriptors. Remote
            // cloud pipes must first be saved as local DocumentsProvider files.
            val channel = FileInputStream(descriptor.fileDescriptor).channel
            val size = runCatching { channel.size() }.getOrElse {
                error("A local, seekable firmware document is required. Save the file locally first.")
            }
            require(size >= 0) { "Invalid document size" }
            val header = readPrefix(channel, minOf(size, 512L).toInt())
            val role = SamsungFirmwareArchive.role(filename)
            val archive: FirmwareArchiveIndex?
            val format: String
            val version: Int?
            val notes = mutableListOf<String>()

            when {
                filename.endsWith(".enc4", true) || filename.endsWith(".enc2", true) -> {
                    archive = null
                    format = "Encrypted Samsung firmware"
                    version = null
                    notes += "Decrypt the package offline to inspect partition filenames."
                }
                SamsungFirmwareArchive.isTar(channel) -> {
                    archive = SamsungFirmwareArchive.scanTar(channel, filename)
                    format = archive.format
                    version = null
                }
                SamsungFirmwareArchive.isZip(channel) -> {
                    archive = SamsungFirmwareArchive.scanZip(channel)
                    format = archive.format
                    version = null
                }
                else -> {
                    archive = null
                    val detected = identify(header)
                    format = detected.first
                    version = detected.second
                    if (filename.endsWith(".tar.md5", true) || filename.endsWith(".tar", true)) {
                        notes += "TAR header checksum invalid or archive truncated; no partitions indexed."
                    }
                }
            }
            currentCoroutineContext().ensureActive()
            val hash = if (size <= HASH_MAX_BYTES) {
                computeHash(channel)
            } else {
                notes += "SHA-256 skipped for files over 32 MiB. Metadata indexed without extraction."
                null
            }
            FirmwareInspection(
                name = filename,
                sizeBytes = size,
                sha256 = hash,
                format = format,
                bootHeaderVersion = version,
                packageRole = role,
                entries = archive?.entries.orEmpty(),
                warnings = archive?.warnings.orEmpty() + notes,
                truncated = archive?.truncated ?: false,
            )
        } ?: error("Unable to open selected firmware file")
    }

    private fun readPrefix(channel: SeekableByteChannel, count: Int): ByteArray {
        channel.position(0)
        val buffer = ByteBuffer.allocate(count)
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) break
        }
        return buffer.array().copyOf(buffer.position())
    }

    private suspend fun computeHash(channel: SeekableByteChannel): String {
        val digest = MessageDigest.getInstance("SHA-256")
        channel.position(0)
        val bytes = ByteBuffer.allocate(64 * 1024)
        while (true) {
            currentCoroutineContext().ensureActive()
            bytes.clear()
            val count = channel.read(bytes)
            if (count < 0) break
            if (count > 0) digest.update(bytes.array(), 0, count)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
