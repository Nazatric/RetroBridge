package dev.retrobridge.app

import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Bounded, read-only ELF preflight for native objects stored inside an APK.
 * Passing it is structural metadata only; it does not prove linkability or guest loadability.
 */
data class NativeElfPreflightResult(
    val archivePath: String,
    val abi: String,
    val elfClass: Int? = null,
    val machine: Int? = null,
    val loadSegmentCount: Int = 0,
    val totalLoadMemoryBytes: Long = 0,
    val diagnostic: String? = null,
) {
    val passesBoundedPreflight: Boolean get() = diagnostic == null
}

object NativeElfPreflight {
    private data class AbiExpectation(val elfClass: Int, val machine: Int)

    private val abiExpectations = mapOf(
        "armeabi" to AbiExpectation(elfClass = 1, machine = 40),
        "armeabi-v7a" to AbiExpectation(elfClass = 1, machine = 40),
        "arm64-v8a" to AbiExpectation(elfClass = 2, machine = 183),
        "x86" to AbiExpectation(elfClass = 1, machine = 3),
        "x86_64" to AbiExpectation(elfClass = 2, machine = 62),
        "riscv64" to AbiExpectation(elfClass = 2, machine = 243),
    )

    private const val ELF_HEADER_32_SIZE = 52
    private const val ELF_HEADER_64_SIZE = 64
    private const val PROGRAM_HEADER_32_SIZE = 32
    private const val PROGRAM_HEADER_64_SIZE = 56
    private const val ET_DYN = 3
    private const val PT_LOAD = 1
    private const val MAX_PROGRAM_HEADERS = 1024
    private const val MAX_PROGRAM_HEADER_TABLE_BYTES = 64 * 1024
    private const val MAX_PROGRAM_HEADER_OFFSET = 1024L * 1024L
    private const val MAX_LIBRARY_FILE_BYTES = 512L * 1024L * 1024L
    private const val MAX_TOTAL_LOAD_BYTES = 1024L * 1024L * 1024L

    /** Reads only the ELF header and bounded program-header table; it never extracts the entry. */
    fun inspect(
        abi: String,
        archivePath: String,
        entrySize: Long,
        input: InputStream,
    ): NativeElfPreflightResult {
        fun invalid(message: String, elfClass: Int? = null, machine: Int? = null) =
            NativeElfPreflightResult(archivePath, abi, elfClass, machine, diagnostic = message)

        val pathParts = archivePath.split('/')
        if (pathParts.size != 3 || pathParts[0] != "lib" || pathParts[1] != abi
            || !pathParts[2].endsWith(".so") || pathParts[2].length <= 3
        ) {
            return invalid("native library path is not lib/<abi>/<name>.so")
        }
        val expectation = abiExpectations[abi] ?: return invalid("ABI folder is not recognized")
        if (entrySize < ELF_HEADER_32_SIZE || entrySize > MAX_LIBRARY_FILE_BYTES) {
            return invalid("library size is outside the preflight bounds")
        }

        return try {
            val ident = readExact(input, 16)
            if (ident[0] != 0x7f.toByte() || ident[1] != 'E'.code.toByte()
                || ident[2] != 'L'.code.toByte() || ident[3] != 'F'.code.toByte()
            ) return invalid("ELF magic is missing")
            val elfClass = ident[4].toInt() and 0xff
            if (elfClass != expectation.elfClass) return invalid("ELF class does not match the ABI", elfClass)
            if ((ident[5].toInt() and 0xff) != 1) return invalid("ELF must be little-endian", elfClass)
            if ((ident[6].toInt() and 0xff) != 1) return invalid("ELF identification version is invalid", elfClass)

            val headerSize = if (elfClass == 1) ELF_HEADER_32_SIZE else ELF_HEADER_64_SIZE
            val header = ident + readExact(input, headerSize - ident.size)
            val headerBuffer = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
            val type = unsignedShort(headerBuffer, 16)
            val machine = unsignedShort(headerBuffer, 18)
            if (headerBuffer.getInt(20) != 1) return invalid("ELF header version is invalid", elfClass, machine)
            if (type != ET_DYN) return invalid("native library is not an ET_DYN shared object", elfClass, machine)
            if (machine != expectation.machine) return invalid("ELF machine does not match the ABI folder", elfClass, machine)

            val phoff: Long
            val phentsize: Int
            val phnum: Int
            val declaredHeaderSize: Int
            if (elfClass == 1) {
                phoff = unsignedInt(headerBuffer, 28)
                declaredHeaderSize = unsignedShort(headerBuffer, 40)
                phentsize = unsignedShort(headerBuffer, 42)
                phnum = unsignedShort(headerBuffer, 44)
            } else {
                phoff = headerBuffer.getLong(32)
                declaredHeaderSize = unsignedShort(headerBuffer, 52)
                phentsize = unsignedShort(headerBuffer, 54)
                phnum = unsignedShort(headerBuffer, 56)
            }
            if (declaredHeaderSize < headerSize || declaredHeaderSize.toLong() > entrySize) {
                return invalid("ELF header size is outside the library", elfClass, machine)
            }
            val minimumPhSize = if (elfClass == 1) PROGRAM_HEADER_32_SIZE else PROGRAM_HEADER_64_SIZE
            if (phoff < declaredHeaderSize || phoff > MAX_PROGRAM_HEADER_OFFSET || phnum == 0 || phnum > MAX_PROGRAM_HEADERS) {
                return invalid("program-header offset or count is outside the preflight bounds", elfClass, machine)
            }
            if (phentsize < minimumPhSize || phentsize > 256) {
                return invalid("program-header entry size is invalid", elfClass, machine)
            }
            val tableBytes = phnum.toLong() * phentsize
            val tableEnd = phoff + tableBytes
            if (tableBytes > MAX_PROGRAM_HEADER_TABLE_BYTES || tableEnd < phoff
                || tableEnd > entrySize || tableEnd > MAX_PROGRAM_HEADER_OFFSET
            ) {
                return invalid("program-header table exceeds the library or preflight bounds", elfClass, machine)
            }

            skipExact(input, phoff - headerSize)
            val table = readExact(input, tableBytes.toInt())
            var loadSegmentCount = 0
            var totalLoadBytes = 0L
            for (index in 0 until phnum) {
                val offset = index * phentsize
                val program = ByteBuffer.wrap(table, offset, minimumPhSize).slice().order(ByteOrder.LITTLE_ENDIAN)
                val kind = program.getInt(0)
                if (kind != PT_LOAD) continue
                val fileOffset: Long
                val virtualAddress: Long
                val fileSize: Long
                val memorySize: Long
                val alignment: Long
                if (elfClass == 1) {
                    fileOffset = unsignedInt(program, 4)
                    virtualAddress = unsignedInt(program, 8)
                    fileSize = unsignedInt(program, 16)
                    memorySize = unsignedInt(program, 20)
                    alignment = unsignedInt(program, 28)
                } else {
                    fileOffset = program.getLong(8)
                    virtualAddress = program.getLong(16)
                    fileSize = program.getLong(32)
                    memorySize = program.getLong(40)
                    alignment = program.getLong(48)
                    if (fileOffset < 0 || virtualAddress < 0 || fileSize < 0 || memorySize < 0 || alignment < 0) {
                        return invalid("ELF64 load segment contains an unsupported unsigned value", elfClass, machine)
                    }
                }
                if (memorySize == 0L || fileSize > memorySize || fileOffset > entrySize
                    || fileSize > entrySize - fileOffset
                ) {
                    return invalid("PT_LOAD file range is outside the library or memory size is invalid", elfClass, machine)
                }
                if (elfClass == 1 && virtualAddress + memorySize > 0x1_0000_0000L) {
                    return invalid("ELF32 PT_LOAD virtual range exceeds the 32-bit address space", elfClass, machine)
                }
                if (elfClass == 2 && virtualAddress > Long.MAX_VALUE - memorySize) {
                    return invalid("ELF64 PT_LOAD virtual range overflows", elfClass, machine)
                }
                if (alignment > 1 && ((alignment and (alignment - 1)) != 0L
                        || virtualAddress % alignment != fileOffset % alignment)
                ) {
                    return invalid("PT_LOAD alignment is invalid", elfClass, machine)
                }
                if (memorySize > MAX_TOTAL_LOAD_BYTES - totalLoadBytes) {
                    return invalid("total PT_LOAD memory exceeds the preflight limit", elfClass, machine)
                }
                loadSegmentCount++
                totalLoadBytes += memorySize
            }
            if (loadSegmentCount == 0) return invalid("ELF has no PT_LOAD segment", elfClass, machine)
            NativeElfPreflightResult(
                archivePath = archivePath,
                abi = abi,
                elfClass = elfClass,
                machine = machine,
                loadSegmentCount = loadSegmentCount,
                totalLoadMemoryBytes = totalLoadBytes,
            )
        } catch (failure: IOException) {
            invalid("ELF header/program table could not be read: ${failure.message ?: "truncated stream"}")
        } catch (failure: ArithmeticException) {
            invalid("ELF header/program table arithmetic overflowed")
        } catch (failure: IndexOutOfBoundsException) {
            invalid("ELF header/program table is truncated")
        }
    }

    private fun readExact(input: InputStream, size: Int): ByteArray {
        val result = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val read = input.read(result, offset, size - offset)
            if (read < 0) throw IOException("unexpected end of ELF entry")
            if (read == 0) {
                val single = input.read()
                if (single < 0) throw IOException("unexpected end of ELF entry")
                result[offset++] = single.toByte()
            } else {
                offset += read
            }
        }
        return result
    }

    private fun skipExact(input: InputStream, size: Long) {
        var remaining = size
        val scratch = ByteArray(8192)
        while (remaining > 0) {
            val skipped = input.skip(remaining)
            if (skipped > 0) {
                remaining -= skipped
            } else {
                val read = input.read(scratch, 0, minOf(scratch.size.toLong(), remaining).toInt())
                if (read < 0) throw IOException("unexpected end of ELF entry before program headers")
                if (read == 0) {
                    if (input.read() < 0) throw IOException("unexpected end of ELF entry before program headers")
                    remaining--
                } else {
                    remaining -= read
                }
            }
        }
    }

    private fun unsignedShort(buffer: ByteBuffer, offset: Int): Int = buffer.getShort(offset).toInt() and 0xffff

    private fun unsignedInt(buffer: ByteBuffer, offset: Int): Long = buffer.getInt(offset).toLong() and 0xffff_ffffL
}
