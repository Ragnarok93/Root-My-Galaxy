package dev.busung.s25uroot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootImageExtractorTest {
    private val lz4 = byteArrayOf(0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0, 0, 0, 0)

    @Test
    fun extractsBootOnlyFromDirectAPTarMd5() {
        val tar = tarOf(
            "system.img.lz4" to ByteArray(128 * 1024),
            "boot.img.lz4" to lz4,
            "vendor.img.lz4" to ByteArray(128 * 1024),
        )
        val out = ByteArrayOutputStream()
        val result = BootImageExtractor.extract(
            ByteArrayInputStream(tar), "AP_G986U1UESCHXL1.tar.md5", out,
        )
        assertArrayEquals(lz4, out.toByteArray())
        assertEquals("boot.img.lz4", result.sourceEntry)
        assertEquals(null, result.packageEntry)
        assertEquals(lz4.size.toLong(), result.sizeBytes)
        assertEquals(
            "33f72dfec4bdbda4c604d6b54118d2bce3568213f784dce413ccff2079480862",
            result.sha256,
        )
    }

    @Test
    fun streamsBootFromDeflatedNestedAPWithoutUnpackingTheRest() {
        val tar = tarOf(
            "images/system.img.lz4" to ByteArray(256 * 1024),
            "images/boot.img.lz4" to lz4,
            "images/vendor.img.lz4" to ByteArray(256 * 1024),
        )
        val zipBytes = zipOf(
            "README.txt" to "firmware package".toByteArray(),
            "AP_G986U1UESCHXL1.tar.md5" to tar,
            "BL_G986U1UESCHXL1.tar.md5" to ByteArray(1024),
        )
        val out = ByteArrayOutputStream()
        val result = BootImageExtractor.extract(
            ByteArrayInputStream(zipBytes),
            "SAMFW.COM_SM-G986U1_XAA_G986U1UESCHXL1_fac.zip",
            out,
        )
        assertArrayEquals(lz4, out.toByteArray())
        assertEquals("images/boot.img.lz4", result.sourceEntry)
        assertEquals("AP_G986U1UESCHXL1.tar.md5", result.packageEntry)
    }

    @Test
    fun failsWithoutWritingIfBootDoesNotExist() {
        val out = ByteArrayOutputStream()
        val err = runCatching {
            BootImageExtractor.extract(
                ByteArrayInputStream(tarOf("vendor.img.lz4" to lz4)),
                "AP_test.tar.md5", out,
            )
        }.exceptionOrNull()
        assertTrue(err is IllegalStateException)
        assertTrue(err?.message?.contains("not found") == true)
        assertEquals(0, out.size())
    }

    @Test
    fun rejectsBadLz4MagicBeforeAnyOutput() {
        val out = ByteArrayOutputStream()
        val err = runCatching {
            BootImageExtractor.extract(
                ByteArrayInputStream(tarOf("boot.img.lz4" to byteArrayOf(1, 2, 3, 4, 5))),
                "AP_test.tar.md5", out,
            )
        }.exceptionOrNull()
        assertTrue(err is IllegalStateException)
        assertTrue(err?.message?.contains("standard LZ4 frame") == true)
        assertEquals(0, out.size())
    }

    @Test
    fun refusesEncryptedFirmwareAndZipWithoutAp() {
        val err = runCatching {
            BootImageExtractor.extract(
                ByteArrayInputStream(byteArrayOf(1, 2, 3, 4)),
                "AP_test.enc4", ByteArrayOutputStream(),
            )
        }.exceptionOrNull()
        assertTrue(err?.message?.contains("Encrypted firmware") == true)
        val missing = runCatching {
            BootImageExtractor.extract(
                ByteArrayInputStream(zipOf("BL_test.tar.md5" to ByteArray(2))),
                "factory.zip", ByteArrayOutputStream(),
            )
        }.exceptionOrNull()
        assertTrue(missing?.message?.contains("AP TAR") == true)
    }

    @Test
    fun reportsProgressAndHonorsCancellationBeforeWritingBoot() {
        val tar = tarOf(
            "super.img.lz4" to ByteArray(9 * 1024 * 1024),
            "boot.img.lz4" to lz4,
        )
        val out = ByteArrayOutputStream()
        var updates = 0
        val problem = runCatching {
            BootImageExtractor.extract(
                ByteArrayInputStream(tar),
                "AP_test.tar",
                out,
                progress = { updates++ },
                checkCancelled = { if (updates > 0) error("cancel requested") },
            )
        }.exceptionOrNull()
        assertTrue(updates > 0)
        assertTrue(problem?.message?.contains("cancel requested") == true)
        assertEquals(0, out.size())
    }

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun tarOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        entries.forEach { (name, bytes) ->
            out.write(tarHeader(name, bytes.size.toLong()))
            out.write(bytes)
            out.write(ByteArray((512 - bytes.size % 512) % 512))
        }
        out.write(ByteArray(1024))
        out.write("0123456789abcdef0123456789abcdef".toByteArray())
        return out.toByteArray()
    }

    private fun tarHeader(name: String, size: Long): ByteArray {
        val bytes = ByteArray(512)
        name.toByteArray().copyInto(bytes)
        (size.toString(8).padStart(11, '0') + "\u0000").toByteArray()
            .copyInto(bytes, 124)
        bytes[156] = '0'.code.toByte()
        "ustar\u0000".toByteArray().copyInto(bytes, 257)
        for (i in 148..155) bytes[i] = ' '.code.toByte()
        val checksum = bytes.sumOf { it.toInt() and 255 }
        (checksum.toString(8).padStart(6, '0') + "\u0000 ")
            .toByteArray().copyInto(bytes, 148)
        return bytes
    }
}
