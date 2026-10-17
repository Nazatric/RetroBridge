package dev.retrobridge.runtime

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GuestRuntimeContextTest {
    @Test
    fun createsAppPrivateContextWithBoundedNativeExecutionLimitations() {
        val fixture = newGuestFixture()
        val context = GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)

        assertEquals(fixture.packageName, context.packageName)
        assertEquals(fixture.appRoot.resolve("app/base.apk"), context.apkPath)
        assertEquals(fixture.appRoot.resolve("internal/files/save.dat"), context.resolveGuestPath(
            "/data/data/${fixture.packageName}/files/save.dat",
        ))
        assertEquals(fixture.appRoot.resolve("external/data/cache/item"), context.resolveGuestPath(
            "/storage/emulated/0/Android/data/${fixture.packageName}/cache/item",
        ))
        assertEquals(fixture.appRoot.resolve("obb/main.1.${fixture.packageName}.obb"), context.resolveGuestPath(
            "/sdcard/Android/obb/${fixture.packageName}/main.1.${fixture.packageName}.obb",
        ))
        assertTrue(GuestFrameworkCapability.APP_PRIVATE_PATH_MAPPING in context.frameworkCapabilities)
        assertTrue(context.nativeExecutionLimitations.contains("Java bytecode"))
    }

    @Test
    fun rejectsUnknownRootsTraversalAndWrongApkDigest() {
        val fixture = newGuestFixture()
        val context = GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)

        assertThrows(SecurityException::class.java) {
            context.resolveGuestPath("/system/lib/libc.so")
        }
        assertThrows(SecurityException::class.java) {
            context.resolveGuestPath("/data/data/${fixture.packageName}/files/../../outside")
        }
        assertThrows(SecurityException::class.java) {
            GuestRuntimeContextFactory.create(
                fixture.privateRoot,
                fixture.request.copy(apkSha256 = "0".repeat(64)),
            )
        }
    }

    @Test
    fun launchesAndStopsOnlyAfterFakeInterpreterReportsRealExecution() {
        val fixture = newGuestFixture(
            nativeLibraries = linkedMapOf(
                "lib/armeabi-v7a/libfoo.so" to byteArrayOf(1, 2, 3, 4),
                "lib/armeabi-v7a/libbar.so" to byteArrayOf(5, 6, 7, 8),
            ),
        )
        val native = FakeNativeRuntimeController()
        val supervisor = GuestRuntimeSessionSupervisor(fixture.privateRoot, { 100L }, native)

        val first = supervisor.startGuestRuntimeSession(fixture.request)
        val duplicate = supervisor.startGuestRuntimeSession(fixture.request)
        assertEquals(GuestRuntimeSessionState.RUNNING, first.state)
        assertEquals(first.sessionId, duplicate.sessionId)
        assertEquals(1, supervisor.activeSessionCount())
        assertTrue(first.guestCodeStarted)
        assertEquals(123L, first.guestInstructions)
        assertEquals(4, first.relocationCount)
        assertEquals(0x00010006, first.jniOnLoadVersion)
        assertEquals(2, first.registeredNativeCount)
        assertEquals(listOf("libbar.so", "libfoo.so"), native.loadedFileNames)
        assertEquals(100L, first.startedAtEpochMs)
        val sessionId = first.sessionId ?: error("Expected an active interpreter session")

        val stopped = supervisor.stopSession(sessionId)
        assertEquals(GuestRuntimeSessionState.STOPPED, stopped.state)
        assertTrue(stopped.guestCodeStarted)
        assertEquals(0, supervisor.activeSessionCount())
        assertEquals(1, native.destroyedSessionCount)
        assertEquals(GuestRuntimeSessionState.NOT_RUNNING, supervisor.stopSession(sessionId).state)
    }

    @Test
    fun refusesApksWithoutAnArm32NativeLibraryInsteadOfClaimingLaunch() {
        val fixture = newGuestFixture()
        val native = FakeNativeRuntimeController()
        val supervisor = GuestRuntimeSessionSupervisor(fixture.privateRoot, { 100L }, native)

        val result = supervisor.startGuestRuntimeSession(fixture.request)
        assertEquals(GuestRuntimeSessionState.UNSUPPORTED, result.state)
        assertFalse(result.guestCodeStarted)
        assertTrue(result.diagnostic.contains("no armeabi", ignoreCase = true))
        assertEquals(0, native.createdSessionCount)
    }

    @Test
    fun rejectsSymlinkedApkAndMissingGuestStorage() {
        val fixture = newGuestFixture()
        assertThrows(java.io.IOException::class.java) {
            GuestRuntimeContextFactory.create(Files.createTempDirectory("retrobridge-runtime-missing"), fixture.request)
        }
        val external = Files.createTempFile("retrobridge-runtime-outside", ".apk")
        Files.write(external, fixture.apkBytes)
        Files.delete(fixture.appRoot.resolve("app/base.apk"))
        val apkPath = fixture.appRoot.resolve("app/base.apk")
        try {
            Files.createSymbolicLink(apkPath, external)
        } catch (_: UnsupportedOperationException) {
            Files.deleteIfExists(external)
            return
        } catch (_: java.io.IOException) {
            Files.deleteIfExists(external)
            return
        } catch (_: SecurityException) {
            Files.deleteIfExists(external)
            return
        }

        try {
            assertThrows(SecurityException::class.java) {
                GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)
            }
        } finally {
            Files.deleteIfExists(apkPath)
            Files.deleteIfExists(external)
        }
    }

    private fun newGuestFixture(
        nativeLibraries: Map<String, ByteArray> = emptyMap(),
    ): GuestFixture {
        val privateRoot = Files.createTempDirectory("retrobridge-runtime-context")
        val packageName = "org.example.runtime"
        val guestId = UUID.randomUUID().toString()
        val appRoot = privateRoot.resolve("apps/$packageName/$guestId")
        val apkPath = appRoot.resolve("app/base.apk")
        Files.createDirectories(apkPath.parent)
        Files.createDirectories(appRoot.resolve("internal/files"))
        Files.createDirectories(appRoot.resolve("external/data"))
        Files.createDirectories(appRoot.resolve("obb"))
        val apkBytes = makeApk(nativeLibraries)
        Files.write(apkPath, apkBytes)
        val digest = MessageDigest.getInstance("SHA-256").digest(apkBytes)
            .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        return GuestFixture(
            privateRoot = privateRoot,
            packageName = packageName,
            guestId = guestId,
            appRoot = appRoot,
            apkBytes = apkBytes,
            request = GuestRuntimeContextRequest(
                guestId = guestId,
                packageName = packageName,
                apkSha256 = digest,
                guestAbis = listOf("armeabi-v7a"),
            ),
        )
    }

    private fun makeApk(nativeLibraries: Map<String, ByteArray>): ByteArray =
        ByteArrayOutputStream().use { output ->
            ZipOutputStream(output).use { zip ->
                zip.putNextEntry(ZipEntry("assets/identity.txt"))
                zip.write("retrobridge-test-apk".toByteArray())
                zip.closeEntry()
                nativeLibraries.forEach { (name, contents) ->
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(contents)
                    zip.closeEntry()
                }
            }
            output.toByteArray()
        }

    private data class GuestFixture(
        val privateRoot: Path,
        val packageName: String,
        val guestId: String,
        val appRoot: Path,
        val apkBytes: ByteArray,
        val request: GuestRuntimeContextRequest,
    )

    private class FakeNativeRuntimeController : NativeRuntimeController {
        val loadedFileNames = mutableListOf<String>()
        var createdSessionCount = 0
        var destroyedSessionCount = 0

        override fun createSession(context: GuestRuntimeContext): Long {
            createdSessionCount++
            return 41L
        }

        override fun inspectLibrary(sessionId: Long, libraryPath: String): NativeLibraryMetadata {
            val fileName = Path.of(libraryPath).fileName.toString()
            val dependencies = if (fileName == "libfoo.so") arrayOf("libbar.so") else emptyArray()
            return NativeLibraryMetadata(true, fileName, fileName, dependencies, "")
        }

        override fun loadLibrary(sessionId: Long, libraryPath: String, expectedSha256: String): NativeLoadResult {
            val fileName = Path.of(libraryPath).fileName.toString()
            loadedFileNames += fileName
            return NativeLoadResult(true, fileName, 0x40000000L, emptyArray(), "")
        }

        override fun execute(sessionId: Long, instructionBudget: Long) = NativeExecutionReport(
            success = true,
            guestInstructions = 123,
            relocationCount = 4,
            jniOnLoadVersion = 0x00010006,
            registeredNativeCount = 2,
            loadedLibraries = loadedFileNames.toTypedArray(),
            entrypointResults = arrayOf("libfoo.so!retrobridge_main => 7"),
            diagnostics = emptyArray(),
        )

        override fun destroySession(sessionId: Long) {
            destroyedSessionCount++
        }
    }
}
