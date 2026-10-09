package dev.busung.s25uroot

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SeekableByteChannel
import java.nio.charset.Charset
import kotlin.math.min

/** One partition candidate in an unextracted Odin archive. */
internal data class FirmwareArchiveEntry(
    val path: String,
    val category: String,
    val format: String,
    val sizeBytes: Long,
    val compressedBytes: Long?,
    val payloadOffset: Long?,
    val note: String,
)

internal data class FirmwareArchiveIndex(
    val format: String,
    val entries: List<FirmwareArchiveEntry>,
    val warnings: List<String> = emptyList(),
    val truncated: Boolean = false,
)

/**
 * Metadata-only parser for Samsung Odin .tar/.tar.md5 and ZIP packages.
 *
 * Uses random-access file-channel reads of 512-byte TAR headers and ZIP central
 * directory records. Never extracts, inflates, writes to, or copies payloads.
 * Works with multi-GB archives; total parsing memory is capped at ~a few MiB.
 * A seekable SAF document is required, so cloud providers may require a local copy.
 */
internal object SamsungFirmwareArchive {
    const val MAX_ENTRIES = 4096
    private const val HEADER_SIZE = 512L
    private const val MAX_LONG_NAME = 16 * 1024
    private val CP437 = Charset.forName("IBM437")

    fun role(name: String): String {
        val upper = name.substringAfterLast('/').uppercase()
        return when {
            upper.startsWith("HOME_CSC_") -> "HOME_CSC"
            upper.startsWith("CSC_") -> "CSC"
            upper.startsWith("AP_") -> "AP"
            upper.startsWith("BL_") -> "BL"
            upper.startsWith("CP_") -> "CP"
            else -> "Unknown"
        }
    }

    fun partition(path: String): String {
        val lower = path.substringAfterLast('/').lowercase()
        val base = lower.removeSuffix(".lz4").removeSuffix(".img")
            .removeSuffix(".bin").removeSuffix(".mbn")
        return when {
            base == "boot" || base == "init_boot" || base == "vendor_boot" || base == "recovery" -> "Boot"
            base.startsWith("vbmeta") || base == "dtbo" || base == "dtb" -> "Verified boot / device tree"
            base == "system" || base == "system_ext" || base == "vendor" ||
                base == "product" || base == "odm" || base == "super" -> "OS / vendor"
            base == "modem" || base == "radio" || base.startsWith("non-hlos") ||
                base == "dsp" || base == "bluetooth" -> "Baseband / firmware"
            base.startsWith("abl") || base.startsWith("xbl") || base == "sboot" ||
                base.startsWith("tz") || base.startsWith("hyp") || base.startsWith("devcfg") ||
                base.startsWith("cmnlib") -> "Bootloader / trust zone"
            base == "userdata" || base == "cache" || base == "metadata" -> "Data / metadata"
            lower.endsWith(".tar") || lower.endsWith(".tar.md5") -> "Nested package"
            else -> "Other"
        }
    }

    private fun typeFromHeader(header: ByteArray, entryName: String): String = when {
        header.size >= 8 && String(header, 0, 8, Charsets.US_ASCII) == "ANDROID!" ->
            "Android boot image"
        starts(header, byteArrayOf(0x04, 0x22, 0x4d, 0x18)) -> "LZ4 frame"
        starts(header, byteArrayOf(0x3a, 0xff.toByte(), 0x26, 0xed.toByte())) ->
            "Android sparse image"
        starts(header, "AVB0".toByteArray()) -> "Android vbmeta"
        starts(header, "VNDRBOOT".toByteArray()) -> "Android vendor_boot"
        starts(header, byteArrayOf(0x7f, 0x45, 0x4c, 0x46)) -> "ELF binary"
        starts(header, byteArrayOf(0x1f, 0x8b.toByte())) -> "gzip"
        starts(header, byteArrayOf(0x28, 0xb5.toByte(), 0x2f, 0xfd.toByte())) -> "zstd"
        entryName.endsWith(".lz4", ignoreCase = true) -> "LZ4 (filename; magic not confirmed)"
        else -> "Unknown / raw"
    }

    private fun starts(bytes: ByteArray, signature: ByteArray): Boolean =
        bytes.size >= signature.size && signature.indices.all { bytes[it] == signature[it] }

    private fun read(channel: SeekableByteChannel, position: Long, count: Int): ByteArray {
        require(position >= 0 && count >= 0) { "Invalid archive range" }
        val end = position + count.toLong()
        require(end >= position && end <= channel.size()) { "Archive header is truncated" }
        val target = ByteBuffer.allocate(count)
        channel.position(position)
        while (target.hasRemaining()) {
            check(channel.read(target) > 0) { "Archive read ended before header was complete" }
        }
        return target.array()
    }

    /** Checks signed and unsigned TAR checksum fields, including old GNU headers. */
    private fun validTarHeader(bytes: ByteArray): Boolean {
        if (bytes.size != 512 || bytes.all { it == 0.toByte() }) return false
        val expected = runCatching { tarNumber(bytes, 148, 8) }.getOrNull() ?: return false
        var unsigned = 0L
        var signed = 0L
        bytes.forEachIndexed { index, b ->
            val value = if (index in 148..155) 32 else b.toInt() and 0xff
            unsigned += value
            signed += if (index in 148..155) 32 else b.toInt()
        }
        return expected == unsigned || expected == signed
    }

    private fun tarNumber(bytes: ByteArray, offset: Int, length: Int): Long {
        val part = bytes.copyOfRange(offset, offset + length)
        if ((part[0].toInt() and 0x80) != 0) {
            require((part[0].toInt() and 0x40) == 0) { "Negative TAR size is invalid" }
            var result = (part[0].toInt() and 0x3f).toLong()
            for (i in 1 until part.size) {
                require(result <= (Long.MAX_VALUE ushr 8)) { "TAR size overflows 64 bits" }
                result = (result shl 8) or (part[i].toLong() and 0xffL)
            }
            return result
        }
        val text = part.toString(Charsets.US_ASCII).trim('\u0000', ' ', '\t')
        return if (text.isEmpty()) 0L else text.toLong(8).also { require(it >= 0) }
    }

    private fun tarString(bytes: ByteArray, start: Int, length: Int): String {
        val end = (start until start + length).firstOrNull { bytes[it] == 0.toByte() }
            ?: start + length
        return String(bytes, start, end - start, Charsets.UTF_8).take(512)
    }

    private fun roundedBlock(size: Long): Long {
        val blocks = size / HEADER_SIZE + if (size % HEADER_SIZE != 0L) 1 else 0
        require(blocks <= Long.MAX_VALUE / HEADER_SIZE) { "TAR size is too large" }
        return blocks * HEADER_SIZE
    }

    private fun md5TrailerPresent(channel: SeekableByteChannel): Boolean {
        val total = channel.size()
        if (total < 32) return false
        val trailer = read(channel, total - min(64, total).toInt(), min(64, total).toInt())
        val end = trailer.toString(Charsets.US_ASCII).trim('\u0000', '\n', '\r', ' ', '\t')
        return end.length >= 32 && end.takeLast(32).all {
            it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F'
        }
    }

    fun isTar(channel: SeekableByteChannel): Boolean =
        channel.size() >= HEADER_SIZE && validTarHeader(read(channel, 0, HEADER_SIZE.toInt()))

    fun isZip(channel: SeekableByteChannel): Boolean =
        channel.size() >= 4 && starts(read(channel, 0, 4), byteArrayOf(0x50, 0x4b, 0x03, 0x04))

    fun scanTar(channel: SeekableByteChannel, fileName: String): FirmwareArchiveIndex {
        val entries = ArrayList<FirmwareArchiveEntry>()
        val warnings = mutableListOf<String>()
        val total = channel.size()
        var offset = 0L
        var pendingName: String? = null
        var ended = false
        var truncated = false
        while (offset + HEADER_SIZE <= total) {
            if (entries.size >= MAX_ENTRIES) {
                truncated = true
                warnings += "Entry limit reached ($MAX_ENTRIES); remaining archive entries were not indexed."
                break
            }
            val header = read(channel, offset, 512)
            if (header.all { it == 0.toByte() }) {
                ended = true
                break
            }
            if (!validTarHeader(header)) {
                warnings += "Invalid TAR header checksum at byte $offset; index may be incomplete."
                break
            }
            val payloadSize = runCatching { tarNumber(header, 124, 12) }.getOrElse {
                warnings += "Invalid TAR entry length at byte $offset"
                break
            }
            val start = offset + HEADER_SIZE
            val padded = runCatching { roundedBlock(payloadSize) }.getOrElse {
                warnings += "Invalid TAR block alignment at byte $offset"
                break
            }
            if (padded > total - start) {
                warnings += "TAR entry exceeds the archive boundary at byte $offset."
                break
            }
            val type = header[156].toInt().toChar()
            val short = tarString(header, 0, 100)
            val prefix = tarString(header, 345, 155)
            val path = (pendingName ?: if (prefix.isBlank()) short else "$prefix/$short").take(512)
            pendingName = null
            if (type == 'L') {
                if (payloadSize <= MAX_LONG_NAME) {
                    pendingName = read(channel, start, payloadSize.toInt()).toString(Charsets.UTF_8)
                        .trimEnd('\u0000', '\n').take(512)
                } else {
                    warnings += "Ignored oversized GNU TAR long filename at $offset"
                }
            } else if (type == '0' || type == '\u0000' || type == '7') {
                val magic = read(channel, start, min(payloadSize, 64L).toInt())
                val fileFormat = typeFromHeader(magic, path)
                entries += FirmwareArchiveEntry(
                    path = path,
                    category = partition(path),
                    format = fileFormat,
                    sizeBytes = payloadSize,
                    compressedBytes = null,
                    payloadOffset = start,
                    note = if (fileFormat.startsWith("LZ4")) {
                        "Compressed partition; contents not decompressed"
                    } else "Header sampled in-place; no extraction",
                )
            } else if (type == 'x' || type == 'g') {
                warnings += "PAX header encountered; extended metadata not applied."
            }
            offset = start + padded
        }
        if (!ended && !truncated && entries.isNotEmpty() && warnings.isEmpty()) {
            warnings += "TAR ended without a complete terminating header."
        }
        if (fileName.endsWith(".tar.md5", ignoreCase = true)) {
            warnings += if (md5TrailerPresent(channel)) "MD5 trailer detected but not cryptographically verified."
                else "MD5 trailer not detected; archive data may still be valid."
        }
        return FirmwareArchiveIndex("Samsung Odin TAR / TAR.MD5", entries, warnings, truncated)
    }

    private fun u16(bytes: ByteArray, index: Int): Int =
        (bytes[index].toInt() and 0xff) or ((bytes[index + 1].toInt() and 0xff) shl 8)

    private fun u32(bytes: ByteArray, index: Int): Long =
        (u16(bytes, index).toLong() or (u16(bytes, index + 2).toLong() shl 16)) and 0xffffffffL

    private fun u64(bytes: ByteArray, index: Int): Long {
        val buffer = ByteBuffer.wrap(bytes, index, 8).order(ByteOrder.LITTLE_ENDIAN)
        return buffer.long.also { require(it >= 0) { "Archive size exceeds supported signed 64-bit range" } }
    }

    fun scanZip(channel: SeekableByteChannel): FirmwareArchiveIndex {
        val total = channel.size()
        require(total >= 22) { "ZIP end of central directory is missing" }
        val tailLength = min(total, 65535L + 22 + 20).toInt()
        val tailBase = total - tailLength
        val tail = read(channel, tailBase, tailLength)
        var eocd = -1
        for (i in tail.size - 22 downTo 0) {
            if (u32(tail, i) == 0x06054b50L && i + 22 + u16(tail, i + 20) == tail.size) {
                eocd = i
                break
            }
        }
        require(eocd >= 0) { "ZIP central-directory footer is missing or has unexpected trailing data" }
        val warnings = mutableListOf<String>()
        require(u16(tail, eocd + 4) == 0 && u16(tail, eocd + 6) == 0) {
            "Multi-disk ZIP archives are not supported"
        }
        var entryCount = u16(tail, eocd + 10).toLong()
        var centralSize = u32(tail, eocd + 12)
        var centralStart = u32(tail, eocd + 16)
        if (entryCount == 0xffffL || centralSize == 0xffffffffL ||
            centralStart == 0xffffffffL) {
            val locatorOffset = tailBase + eocd - 20
            require(locatorOffset >= 0L) { "ZIP64 locator is missing" }
            val locator = read(channel, locatorOffset, 20)
            require(u32(locator, 0) == 0x07064b50L) { "ZIP64 locator is missing" }
            require(u32(locator, 4) == 0L && u32(locator, 16) == 1L) {
                "Multi-disk ZIP64 is not supported"
            }
            val zip64 = read(channel, u64(locator, 8), 56)
            require(u32(zip64, 0) == 0x06064b50L) { "ZIP64 end header is invalid" }
            entryCount = u64(zip64, 32)
            centralSize = u64(zip64, 40)
            centralStart = u64(zip64, 48)
        }
        require(centralStart <= total && centralSize <= total - centralStart) {
            "ZIP central directory points outside the file"
        }
        var position = centralStart
        val end = centralStart + centralSize
        val entries = mutableListOf<FirmwareArchiveEntry>()
        val limit = min(entryCount, MAX_ENTRIES.toLong()).toInt()
        for (entryIndex in 0 until limit) {
            require(position + 46 <= end) { "ZIP entry header is truncated" }
            val header = read(channel, position, 46)
            require(u32(header, 0) == 0x02014b50L) {
                "Invalid ZIP central-directory entry at byte $position"
            }
            val flags = u16(header, 8)
            val method = u16(header, 10)
            var storedSize = u32(header, 20)
            var payloadSize = u32(header, 24)
            val nameLength = u16(header, 28)
            val extraLength = u16(header, 30)
            val commentLength = u16(header, 32)
            val headerSpan = 46L + nameLength + extraLength + commentLength
            require(position + headerSpan <= end) { "ZIP metadata overflows central directory" }
            val rawName = read(channel, position + 46, nameLength)
            val path = String(rawName, if (flags and (1 shl 11) != 0) Charsets.UTF_8 else CP437)
                .take(512)
            val extra = read(channel, position + 46 + nameLength, extraLength)
            if (payloadSize == 0xffffffffL || storedSize == 0xffffffffL) {
                var cursor = 0
                var resolved = false
                while (cursor + 4 <= extra.size) {
                    val type = u16(extra, cursor)
                    val length = u16(extra, cursor + 2)
                    require(cursor + 4 + length <= extra.size) { "Invalid ZIP extra data length" }
                    if (type == 1) {
                        var at = cursor + 4
                        val extraEnd = at + length
                        if (payloadSize == 0xffffffffL) {
                            require(at + 8 <= extraEnd) { "ZIP64 uncompressed length missing" }
                            payloadSize = u64(extra, at)
                            at += 8
                        }
                        if (storedSize == 0xffffffffL) {
                            require(at + 8 <= extraEnd) { "ZIP64 stored length missing" }
                            storedSize = u64(extra, at)
                        }
                        resolved = true
                        break
                    }
                    cursor += 4 + length
                }
                require(resolved) { "Missing ZIP64 size metadata" }
            }
            if (!path.endsWith('/')) {
                entries += FirmwareArchiveEntry(
                    path = path,
                    category = partition(path),
                    format = when (method) { 0 -> "Stored"; 8 -> "DEFLATE"; else -> "ZIP method $method" },
                    sizeBytes = payloadSize,
                    compressedBytes = storedSize,
                    payloadOffset = null,
                    note = if (path.endsWith(".tar.md5", true) || path.endsWith(".tar", true))
                        "Nested Odin package indexed by name only; select TAR separately for partition inventory"
                    else "ZIP central-directory metadata only; entry contents not read",
                )
            }
            position += headerSpan
        }
        if (entryCount > MAX_ENTRIES) {
            warnings += "Indexed first $MAX_ENTRIES of $entryCount ZIP entries."
        }
        return FirmwareArchiveIndex(
            format = "ZIP package (central directory only)",
            entries = entries,
            warnings = warnings,
            truncated = entryCount > MAX_ENTRIES,
        )
    }
}
