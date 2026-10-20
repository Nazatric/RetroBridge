package dev.retrobridge.app

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ApkImporterStreamTest {
    @Test
    fun zeroLengthBulkReadFallsBackWithoutSkippingBytesOrSpinning() {
        val bytes = "arm32-apk".toByteArray(Charsets.UTF_8)
        val source = IntermittentZeroInputStream(bytes)
        val output = ByteArrayOutputStream()
        val digest = MessageDigest.getInstance("SHA-256")

        val copied = copyBoundedAndDigest(source, output, bytes.size.toLong(), digest)

        assertEquals(bytes.size.toLong(), copied)
        assertArrayEquals(bytes, output.toByteArray())
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(bytes), digest.digest())
    }

    @Test
    fun rejectsPayloadOverLimitWithoutWritingTheOversizedChunk() {
        val bytes = "abc".toByteArray(Charsets.UTF_8)
        val output = ByteArrayOutputStream()

        assertThrows(IllegalArgumentException::class.java) {
            copyBoundedAndDigest(
                IntermittentZeroInputStream(bytes),
                output,
                maximumBytes = 2,
                digest = MessageDigest.getInstance("SHA-256"),
            )
        }

        assertArrayEquals(byteArrayOf('a'.code.toByte()), output.toByteArray())
    }

    private class IntermittentZeroInputStream(private val bytes: ByteArray) : InputStream() {
        private var position = 0
        private var returnZero = true

        override fun read(): Int {
            if (position >= bytes.size) return -1
            return bytes[position++].toInt() and 0xff
        }

        override fun read(target: ByteArray, offset: Int, length: Int): Int {
            if (length == 0) return 0
            if (returnZero) {
                returnZero = false
                return 0
            }
            if (position >= bytes.size) return -1
            val count = minOf(length, bytes.size - position)
            bytes.copyInto(target, offset, position, position + count)
            position += count
            return count
        }
    }
}
