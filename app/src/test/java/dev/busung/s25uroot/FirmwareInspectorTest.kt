package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FirmwareInspectorTest {
    @Test
    fun recognizesAndroidBootHeaderVersion() {
        val boot = ByteArray(64)
        "ANDROID!".toByteArray().copyInto(boot, 0)
        boot[40] = 3
        val (format, version) = FirmwareInspector.identify(boot)
        assertEquals("Android boot image", format)
        assertEquals(3, version)
    }

    @Test
    fun recognizesSamsungLz4FramedImage() {
        val lz4 = byteArrayOf(0x04, 0x22, 0x4d, 0x18, 0, 0, 0, 0)
        val (format, version) = FirmwareInspector.identify(lz4)
        assertTrue(format.startsWith("LZ4"))
        assertNull(version)
    }

    @Test
    fun invalidShortHeaderCannotReadVersion() {
        val short = "ANDROID!".toByteArray()
        assertEquals("Unknown / raw binary", FirmwareInspector.identify(short).first)
    }

    @Test
    fun shellProbesAreReadOnlyAndAllowlisted() {
        val probes = InvestigationCollector.probes
        assertTrue(probes.isNotEmpty())
        assertTrue(probes.none {
            it.command.any { argument ->
                argument.contains("dd if=") || argument.contains("setenforce 0") ||
                    argument.contains("su -c") || argument.contains("/dev/block")
            }
        })
        assertTrue(probes.any { it.id == "kernel.trace_event" })
        assertTrue(probes.any { it.id == "ro.boot.bootloader" })
    }
}
