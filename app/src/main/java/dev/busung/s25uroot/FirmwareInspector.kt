package dev.busung.s25uroot

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal data class FirmwareInspection(
    val name: String,
    val sizeBytes: Long,
    val sha256: String,
    val format: String,
    val bootHeaderVersion: Int?,
)

/**
 * Inspects a user-picked, already accessible file. This is NOT a raw partition reader:
 * stock ADB-shell Shizuku cannot dump boot partitions or download a Samsung AP archive.
 * No files are modified, untrusted archives are not unpacked, and no data is uploaded.
 */
internal object FirmwareInspector {
    private const val MAX_FILE_BYTES = 256L * 1024L * 1024L
    private const val MAX_FILE_NAME = 160

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
            return "LZ4-compressed image (decompress offline for kernel analysis)" to null
        }
        if (firstBytes.size >= 4 && firstBytes[0] == 0x50.toByte() &&
            firstBytes[1] == 0x4b.toByte()) {
            return "ZIP archive (metadata only; not extracted)" to null
        }
        if (firstBytes.size >= 262 &&
            firstBytes.copyOfRange(257, 262).contentEquals("ustar".toByteArray(Charsets.US_ASCII))) {
            return "TAR archive (metadata only; not extracted)" to null
        }
        return "Unknown / raw binary" to null
    }

    suspend fun inspect(context: Context, uri: Uri): FirmwareInspection = withContext(Dispatchers.IO) {
        val displayName = context.contentResolver.query(
            uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }?.take(MAX_FILE_NAME) ?: "selected-file"

        val hash = MessageDigest.getInstance("SHA-256")
        val header = ByteArray(512)
        var headerRead = 0
        var total = 0L
        val stream = context.contentResolver.openInputStream(uri)
            ?: error("The selected document cannot be opened")
        stream.use {
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val length = it.read(buffer)
                if (length == -1) break
                if (length == 0) continue
                total += length
                check(total <= MAX_FILE_BYTES) {
                    "File exceeds the 256 MiB inspection limit. Extract boot.img offline first."
                }
                hash.update(buffer, 0, length)
                if (headerRead < header.size) {
                    val lengthToCopy = minOf(length, header.size - headerRead)
                    buffer.copyInto(header, headerRead, 0, lengthToCopy)
                    headerRead += lengthToCopy
                }
            }
        }
        val (format, bootHeaderVersion) = identify(header.copyOf(headerRead))
        FirmwareInspection(
            name = displayName,
            sizeBytes = total,
            sha256 = hash.digest().joinToString("") { "%02x".format(it) },
            format = format,
            bootHeaderVersion = bootHeaderVersion,
        )
    }
}
