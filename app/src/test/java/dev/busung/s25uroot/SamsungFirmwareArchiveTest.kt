package dev.busung.s25uroot

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SamsungFirmwareArchiveTest {
    @Test
    fun recognizesOdinPackageRolesAndPartitionTypes() {
        assertEquals("AP", SamsungFirmwareArchive.role("AP_G986U1_TEST.tar.md5"))
        assertEquals("BL", SamsungFirmwareArchive.role("BL_G986U1_TEST.tar.md5"))
        assertEquals("CP", SamsungFirmwareArchive.role("CP_G986U1_TEST.tar.md5"))
        assertEquals("CSC", SamsungFirmwareArchive.role("CSC_OYM_G986U1.tar.md5"))
        assertEquals("HOME_CSC", SamsungFirmwareArchive.role("HOME_CSC_OYM_G986U1.tar.md5"))
        assertEquals("Boot", SamsungFirmwareArchive.partition("boot.img.lz4"))
        assertEquals("Verified boot / device tree", SamsungFirmwareArchive.partition("vbmeta.img.lz4"))
        assertEquals("Bootloader / trust zone", SamsungFirmwareArchive.partition("xbl.elf"))
    }

    @Test
    fun scansUnextractedOdinTarMd5IncludingLz4AndMd5Trailer() {
        val file = File.createTempFile("AP_G986U1_", ".tar.md5")
        try {
            val content = ByteArrayOutputStream()
            val lz4 = byteArrayOf(0x04, 0x22, 0x4d, 0x18, 1, 2, 3, 4)
            addTarFile(content, "boot.img.lz4", lz4)
            addTarFile(content, "vbmeta.img.lz4", lz4)
            content.write(ByteArray(1024))
            content.write("0123456789abcdef0123456789abcdef".toByteArray())
            file.writeBytes(content.toByteArray())
            file.inputStream().channel.use { channel ->
                assertTrue(SamsungFirmwareArchive.isTar(channel))
                val index = SamsungFirmwareArchive.scanTar(channel, file.name)
                assertEquals(2, index.entries.size)
                assertEquals("boot.img.lz4", index.entries[0].path)
                assertEquals("LZ4 frame", index.entries[0].format)
                assertEquals(512L, index.entries[0].payloadOffset)
                assertEquals("Verified boot / device tree", index.entries[1].category)
                assertTrue(index.warnings.any { it.contains("MD5 trailer detected") })
                assertFalse(index.truncated)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun usesCentralDirectoryForZipWithoutDecompression() {
        val file = File.createTempFile("Samsung_G986U1_", ".zip")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                listOf(
                    "AP_G986U1UESCHXL1.tar.md5",
                    "BL_G986U1UESCHXL1.tar.md5",
                    "CP_G986U1UESCHXL1.tar.md5",
                    "CSC_OYM_G986U1.tar.md5",
                ).forEach { name ->
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(ByteArray(1024))
                    zip.closeEntry()
                }
            }
            file.inputStream().channel.use {
                assertTrue(SamsungFirmwareArchive.isZip(it))
                val index = SamsungFirmwareArchive.scanZip(it)
                assertEquals(4, index.entries.size)
                assertEquals("Nested package", index.entries[0].category)
                assertTrue(index.entries[0].note.contains("select TAR separately"))
                assertTrue(index.entries.all { entry -> entry.payloadOffset == null })
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun indexesSparseTarLargerThanTwoGigabytesWithoutReadingItsPayload() {
        val file = File.createTempFile("AP_G986U1_", ".tar")
        val huge = 3L * 1024L * 1024L * 1024L
        try {
            RandomAccessFile(file, "rw").use { raf ->
                raf.write(header("super.img.lz4", huge))
                raf.seek(512 + huge)
                raf.write(ByteArray(1024))
            }
            file.inputStream().channel.use {
                val index = SamsungFirmwareArchive.scanTar(it, file.name)
                assertEquals(1, index.entries.size)
                assertEquals(huge, index.entries[0].sizeBytes)
                assertEquals("OS / vendor", index.entries[0].category)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun rejectsCorruptedTarHeaderChecksum() {
        val file = File.createTempFile("invalid", ".tar.md5")
        try {
            val corrupted = header("boot.img.lz4", 16)
            corrupted[0] = 'X'.code.toByte()
            file.writeBytes(corrupted)
            file.inputStream().channel.use {
                assertFalse(SamsungFirmwareArchive.isTar(it))
            }
        } finally {
            file.delete()
        }
    }

    private fun addTarFile(out: ByteArrayOutputStream, name: String, bytes: ByteArray) {
        out.write(header(name, bytes.size.toLong()))
        out.write(bytes)
        val pad = (512 - bytes.size % 512) % 512
        out.write(ByteArray(pad))
    }

    private fun header(name: String, length: Long): ByteArray {
        val bytes = ByteArray(512)
        name.toByteArray().copyInto(bytes, 0)
        val size = length.toString(8).padStart(11, '0') + "\u0000"
        size.toByteArray().copyInto(bytes, 124)
        "0000644\u0000".toByteArray().copyInto(bytes, 100)
        "ustar\u0000".toByteArray().copyInto(bytes, 257)
        bytes[156] = '0'.code.toByte()
        for (i in 148..155) bytes[i] = ' '.code.toByte()
        val checksum = bytes.sumOf { it.toInt() and 0xff }
        val octal = checksum.toString(8).padStart(6, '0') + "\u0000 "
        octal.toByteArray().copyInto(bytes, 148)
        return bytes
    }
}
