package dev.retrobridge.runtime

import java.nio.file.Paths
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class NativeLibraryExtractorTest {
    @Test
    fun acceptsVirtualLibstdcxxDependencyForTheExplicitPartialCppAbiShim() {
        val libraryPath = Paths.get("virtual", "libgame.so")
        val library = ExtractedNativeLibrary(
            abi = "armeabi-v7a",
            fileName = "libgame.so",
            path = libraryPath,
            sha256 = "0".repeat(64),
            size = 1,
        )
        val metadata = NativeLibraryMetadata(
            valid = true,
            libraryName = library.fileName,
            soname = library.fileName,
            neededLibraries = arrayOf("libstdc++.so"),
            diagnostic = "",
        )

        assertEquals(
            listOf(library),
            NativeLibraryExtractor.dependencyOrder(listOf(library), mapOf(libraryPath to metadata)),
        )
    }

    @Test
    fun stillRejectsUnknownNonPlatformDependencies() {
        val libraryPath = Paths.get("virtual", "libgame.so")
        val library = ExtractedNativeLibrary(
            abi = "armeabi-v7a",
            fileName = "libgame.so",
            path = libraryPath,
            sha256 = "0".repeat(64),
            size = 1,
        )
        val metadata = NativeLibraryMetadata(
            valid = true,
            libraryName = library.fileName,
            soname = library.fileName,
            neededLibraries = arrayOf("libunknown_platform.so"),
            diagnostic = "",
        )

        val failure = assertThrows(IllegalArgumentException::class.java) {
            NativeLibraryExtractor.dependencyOrder(listOf(library), mapOf(libraryPath to metadata))
        }

        assertTrue(failure.message.orEmpty().contains("libunknown_platform.so"))
    }
}
