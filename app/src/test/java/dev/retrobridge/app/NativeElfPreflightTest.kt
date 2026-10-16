package dev.retrobridge.app

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeElfPreflightTest {
    @Test
    fun acceptsBoundedArm32SharedObjectWithLoadSegment() {
        val bytes = makeElf32()
        val result = NativeElfPreflight.inspect(
            abi = "armeabi-v7a",
            archivePath = "lib/armeabi-v7a/libfixture.so",
            entrySize = bytes.size.toLong(),
            input = ByteArrayInputStream(bytes),
        )

        assertTrue(result.diagnostic.orEmpty(), result.passesBoundedPreflight)
        assertEquals(1, result.elfClass)
        assertEquals(40, result.machine)
        assertEquals(1, result.loadSegmentCount)
        assertEquals(4L, result.totalLoadMemoryBytes)
    }

    @Test
    fun acceptsBoundedArm64SharedObject() {
        val bytes = makeElf64()
        val result = NativeElfPreflight.inspect(
            abi = "arm64-v8a",
            archivePath = "lib/arm64-v8a/libfixture.so",
            entrySize = bytes.size.toLong(),
            input = ByteArrayInputStream(bytes),
        )

        assertTrue(result.diagnostic.orEmpty(), result.passesBoundedPreflight)
        assertEquals(2, result.elfClass)
        assertEquals(183, result.machine)
    }

    @Test
    fun rejectsMachineMismatchAndMalformedProgramRanges() {
        val wrongMachine = makeElf32(machine = 183)
        val machineResult = inspect32(wrongMachine)
        assertFalse(machineResult.passesBoundedPreflight)
        assertTrue(machineResult.diagnostic.orEmpty().contains("machine"))

        val outsideFile = makeElf32().also { bytes ->
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(68, 0x1000)
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(72, 0x1000)
        }
        val rangeResult = inspect32(outsideFile)
        assertFalse(rangeResult.passesBoundedPreflight)
        assertTrue(rangeResult.diagnostic.orEmpty().contains("PT_LOAD"))
    }

    @Test
    fun rejectsOversizedHeaderTableMisalignedLoadAndTruncatedInput() {
        val outsideTable = makeElf32(phoff = 0x200)
        val tableResult = inspect32(outsideTable)
        assertFalse(tableResult.passesBoundedPreflight)
        assertTrue(tableResult.diagnostic.orEmpty().contains("program-header"))

        val misaligned = makeElf32().also { bytes ->
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(60, 0x1001)
        }
        val alignmentResult = inspect32(misaligned)
        assertFalse(alignmentResult.passesBoundedPreflight)
        assertTrue(alignmentResult.diagnostic.orEmpty().contains("alignment"))

        val truncated = inspect32(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        assertFalse(truncated.passesBoundedPreflight)
        assertTrue(truncated.diagnostic.orEmpty().contains("size"))
    }

    @Test
    fun rejectsArchivePathsThatDoNotMatchTheAbiDirectory() {
        val bytes = makeElf32()
        val result = NativeElfPreflight.inspect(
            abi = "armeabi-v7a",
            archivePath = "lib/arm64-v8a/libfixture.so",
            entrySize = bytes.size.toLong(),
            input = ByteArrayInputStream(bytes),
        )
        assertFalse(result.passesBoundedPreflight)
        assertTrue(result.diagnostic.orEmpty().contains("path"))
    }

    private fun inspect32(bytes: ByteArray): NativeElfPreflightResult = NativeElfPreflight.inspect(
        abi = "armeabi-v7a",
        archivePath = "lib/armeabi-v7a/libfixture.so",
        entrySize = bytes.size.toLong(),
        input = ByteArrayInputStream(bytes),
    )

    private fun makeElf32(machine: Int = 40, phoff: Int = 52): ByteArray {
        val bytes = ByteArray(0x104)
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 1
        bytes[5] = 1
        bytes[6] = 1
        buffer.putShort(16, 3)
        buffer.putShort(18, machine.toShort())
        buffer.putInt(20, 1)
        buffer.putInt(28, phoff)
        buffer.putShort(40, 52)
        buffer.putShort(42, 32)
        buffer.putShort(44, 1)
        if (phoff == 52) {
            buffer.putInt(52, 1)       // PT_LOAD
            buffer.putInt(56, 0x100)   // p_offset
            buffer.putInt(60, 0x1000)  // p_vaddr
            buffer.putInt(68, 4)       // p_filesz
            buffer.putInt(72, 4)       // p_memsz
            buffer.putInt(76, 5)       // PF_R | PF_X
            buffer.putInt(80, 0x1000)  // p_align
        }
        return bytes
    }

    private fun makeElf64(): ByteArray {
        val bytes = ByteArray(0x104)
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2
        bytes[5] = 1
        bytes[6] = 1
        buffer.putShort(16, 3)
        buffer.putShort(18, 183)
        buffer.putInt(20, 1)
        buffer.putLong(32, 64)
        buffer.putShort(52, 64)
        buffer.putShort(54, 56)
        buffer.putShort(56, 1)
        buffer.putInt(64, 1)            // PT_LOAD
        buffer.putInt(68, 5)            // PF_R | PF_X
        buffer.putLong(72, 0x100)
        buffer.putLong(80, 0x1000)
        buffer.putLong(88, 0)
        buffer.putLong(96, 4)
        buffer.putLong(104, 4)
        buffer.putLong(112, 0x1000)
        return bytes
    }
}
