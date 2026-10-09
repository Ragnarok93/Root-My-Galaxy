package dev.busung.s25uroot

import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream
import kotlin.math.min

internal data class BootExtractionResult(
    val sourceEntry: String,
    val packageEntry: String?,
    val sizeBytes: Long,
    val sha256: String,
)

/**
 * Extracts only boot.img.lz4 from an Odin AP TAR/TAR.MD5 or an AP TAR
 * nested in a (possibly ZIP64) firmware ZIP. Does not decompress LZ4,
 * stage the AP archive, flash, or touch any device partition.
 *
 * All reads are bounded and streaming. ZIP members preceding the AP entry,
 * and TAR members preceding boot.img.lz4, are drained/discarded; unlike a
 * seekable TAR, they cannot be skipped without decompression. Once the boot
 * entry is copied, scanning stops immediately, so the parent AP ZIP member's
 * CRC/MD5 is NOT verified. Only the extracted boot SHA-256 is computed.
 */
internal object BootImageExtractor {
    private const val BLOCK = 512
    private const val MAX_TAR_MEMBERS = 4096
    private const val MAX_METADATA = 16 * 1024L
    private const val MAX_BOOT_BYTES = 512L * 1024L * 1024L
    private const val MAX_SCAN_BYTES = 16L * 1024L * 1024L * 1024L
    private const val UPDATE_EVERY = 8L * 1024L * 1024L

    fun extract(
        source: InputStream,
        sourceName: String,
        output: OutputStream,
        progress: (Long) -> Unit = {},
        checkCancelled: () -> Unit = {},
    ): BootExtractionResult {
        val prefix = ByteArray(4)
        val markable = java.io.BufferedInputStream(source, 128 * 1024)
        markable.mark(4)
        if (markable.read(prefix) != 4) error("Source is empty or too short")
        markable.reset()
        val isZip = prefix[0] == 0x50.toByte() && prefix[1] == 0x4b.toByte() &&
            (prefix[2] == 0x03.toByte() || prefix[2] == 0x05.toByte()) &&
            (prefix[3] == 0x04.toByte() || prefix[3] == 0x06.toByte())
        return when {
            sourceName.endsWith(".enc4", true) || sourceName.endsWith(".enc2", true) ->
                error("Encrypted firmware is not supported. Obtain a decrypted ZIP or AP TAR.")
            isZip -> extractFromZip(markable, output, progress, checkCancelled)
            else -> scanTar(markable, null, output, progress, checkCancelled)
        }
    }

    private fun extractFromZip(
        source: InputStream,
        output: OutputStream,
        progress: (Long) -> Unit,
        checkCancelled: () -> Unit,
    ): BootExtractionResult {
        ZipInputStream(source, Charsets.UTF_8).use { zip ->
            var files = 0
            while (true) {
                checkCancelled()
                val entry = zip.nextEntry ?: break
                files++
                check(files <= 1024) { "Firmware ZIP has too many entries" }
                val filename = entry.name.substringAfterLast('/')
                if (filename.startsWith("AP_", true) &&
                    (filename.endsWith(".tar.md5", true) || filename.endsWith(".tar", true))) {
                    // Do NOT call closeEntry after success: that would inflate/discard
                    // the remainder of multi-GB AP data and defeat selective extraction.
                    return scanTar(zip, entry.name, output, progress, checkCancelled)
                }
                // closeEntry consumes earlier ZIP entries without storing them.
                zip.closeEntry()
            }
        }
        error("No Samsung AP TAR/TAR.MD5 member found in the firmware ZIP")
    }

    private fun scanTar(
        source: InputStream,
        nestedPackage: String?,
        output: OutputStream,
        progress: (Long) -> Unit,
        checkCancelled: () -> Unit,
    ): BootExtractionResult {
        val header = ByteArray(BLOCK)
        val buffer = ByteArray(128 * 1024)
        val sha = MessageDigest.getInstance("SHA-256")
        var consumed = 0L
        var lastUpdate = 0L
        var pendingLongName: String? = null
        var pendingPaxName: String? = null

        fun bump(count: Long) {
            consumed += count
            check(consumed <= MAX_SCAN_BYTES) { "Archive scan exceeded 16 GiB safety limit" }
            if (consumed - lastUpdate >= UPDATE_EVERY) {
                checkCancelled()
                progress(consumed)
                lastUpdate = consumed
            }
        }

        fun readExact(bytes: ByteArray, length: Int) {
            var offset = 0
            while (offset < length) {
                checkCancelled()
                val count = source.read(bytes, offset, length - offset)
                check(count > 0) { "Truncated TAR payload or header" }
                offset += count
                bump(count.toLong())
            }
        }

        fun discard(length: Long) {
            var remaining = length
            while (remaining > 0) {
                checkCancelled()
                // InputStream.skip is efficient for a local TAR; ZIP input
                // streams inflate to discard without writing to storage.
                // InflaterInputStream.skip may internally discard using tiny
                // buffers. Read ZIP entry data with our 128-KiB scratch buffer
                // instead; only seekable/plain TAR input uses skip().
                val skipped = if (source is ZipInputStream) 0L else
                    source.skip(min(remaining, 1024L * 1024L))
                if (skipped > 0) {
                    remaining -= skipped
                    bump(skipped)
                } else {
                    val n = source.read(buffer, 0, min(remaining, buffer.size.toLong()).toInt())
                    check(n > 0) { "Truncated TAR entry" }
                    remaining -= n
                    bump(n.toLong())
                }
            }
        }

        repeat(MAX_TAR_MEMBERS) {
            readExact(header, BLOCK)
            if (header.all { it == 0.toByte() }) {
                error("boot.img.lz4 was not found in the selected AP TAR")
            }
            check(validHeader(header)) { "Invalid TAR header checksum; extraction stopped" }
            val size = tarSize(header)
            check(size <= MAX_SCAN_BYTES - consumed) { "TAR entry size exceeds scan limit" }
            val type = header[156].toInt().toChar()
            val name = tarString(header, 0, 100)
            val prefix = tarString(header, 345, 155)
            val tarPath = if (prefix.isBlank()) name else "$prefix/$name"
            val path = (pendingPaxName ?: pendingLongName ?: tarPath).take(512)
            if (type != 'L' && type != 'x' && type != 'g') {
                pendingPaxName = null
                pendingLongName = null
            }
            val regular = type == '0' || type == '\u0000' || type == '7'
            val target = path.substringAfterLast('/').equals("boot.img.lz4", ignoreCase = true)
            if (regular && target) {
                check(size in 4..MAX_BOOT_BYTES) {
                    "boot.img.lz4 has an invalid or excessive declared size ($size bytes)"
                }
                val magic = ByteArray(4)
                readExact(magic, 4)
                check(magic.contentEquals(byteArrayOf(0x04, 0x22, 0x4d, 0x18))) {
                    "boot.img.lz4 does not contain a standard LZ4 frame"
                }
                output.write(magic)
                sha.update(magic)
                var remaining = size - 4
                while (remaining > 0L) {
                    checkCancelled()
                    val take = min(remaining, buffer.size.toLong()).toInt()
                    val n = source.read(buffer, 0, take)
                    check(n > 0) { "Truncated boot.img.lz4 data; incomplete output discarded" }
                    output.write(buffer, 0, n)
                    sha.update(buffer, 0, n)
                    remaining -= n
                    bump(n.toLong())
                }
                output.flush()
                progress(consumed)
                return BootExtractionResult(
                    sourceEntry = path,
                    packageEntry = nestedPackage,
                    sizeBytes = size,
                    sha256 = sha.digest().joinToString("") { "%02x".format(it) },
                )
            }
            if (type == 'L' || type == 'x') {
                // GNU longnames and PAX metadata are bounded, unlike image payloads.
                check(size <= MAX_METADATA) { "Oversized TAR name/metadata record" }
                val ext = ByteArray(size.toInt())
                readExact(ext, ext.size)
                val text = ext.toString(Charsets.UTF_8)
                if (type == 'L') pendingLongName = text.trimEnd('\u0000', '\n')
                else pendingPaxName = text.lines().mapNotNull {
                    val candidate = it.substringAfter(" path=", "")
                    candidate.takeIf { value -> value.isNotEmpty() }
                }.lastOrNull()
            } else {
                discard(size)
            }
            // Each TAR entry is padded to the next 512-byte boundary.
            val pad = (BLOCK - (size % BLOCK)).toLong() % BLOCK
            discard(pad)
        }
        error("boot.img.lz4 not found within the first $MAX_TAR_MEMBERS TAR entries")
    }

    private fun tarString(header: ByteArray, offset: Int, size: Int): String {
        val end = (offset until offset + size).firstOrNull { header[it] == 0.toByte() }
            ?: (offset + size)
        return String(header, offset, end - offset, Charsets.UTF_8).take(512)
    }

    private fun tarSize(header: ByteArray): Long {
        val first = header[124].toInt() and 255
        if (first and 0x80 != 0) {
            check(first and 0x40 == 0) { "Negative TAR size" }
            var size = (first and 0x3f).toLong()
            for (i in 125..135) {
                check(size <= Long.MAX_VALUE ushr 8) { "TAR size overflow" }
                size = (size shl 8) or (header[i].toLong() and 255)
            }
            return size
        }
        val size = tarString(header, 124, 12).trim(' ', '\u0000')
        return if (size.isBlank()) 0 else size.toLong(8).also { check(it >= 0) }
    }

    private fun validHeader(header: ByteArray): Boolean {
        val expected = runCatching {
            tarString(header, 148, 8).trim(' ', '\u0000').toLong(8)
        }.getOrNull() ?: return false
        var unsigned = 0L
        var signed = 0L
        header.forEachIndexed { i, byte ->
            unsigned += if (i in 148..155) 32 else byte.toInt() and 255
            signed += if (i in 148..155) 32 else byte.toInt()
        }
        return expected == unsigned || expected == signed
    }
}
