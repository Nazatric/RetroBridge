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
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GuestRuntimeContextTest {
    @Test
    fun createsAppPrivateContextWithBoundedNativeExecutionLimitations() {
        val fixture = newGuestFixture()
        val context = GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)

        assertEquals(fixture.packageName, context.packageName)
        assertEquals("RetroBridge Fixture", context.packageMetadata.applicationLabel)
        assertEquals("2.7", context.packageMetadata.versionName)
        assertEquals(207L, context.packageMetadata.versionCode)
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
        assertTrue(GuestFrameworkCapability.GUEST_SHARED_PREFERENCES in context.frameworkCapabilities)
        assertTrue(GuestFrameworkCapability.BOUNDED_APK_ASSET_READS in context.frameworkCapabilities)
        assertTrue(context.nativeExecutionLimitations.contains("Java bytecode"))
    }

    @Test
    fun contextFacadeProvidesGuestPathsPreferencesAssetsAndOnePackageSnapshot() {
        val fixture = newGuestFixture()
        val context = GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)
        val wrapper = GuestContextWrapper(context)
        wrapper.prepareStorageDirectories()

        assertEquals(fixture.appRoot.resolve("internal/files"), wrapper.filesDir)
        assertEquals(fixture.appRoot.resolve("internal/cache"), wrapper.cacheDir)
        assertEquals(fixture.appRoot.resolve("internal/shared_prefs"), wrapper.sharedPreferencesDir)
        assertEquals(fixture.appRoot.resolve("external/data/files/Pictures"), wrapper.externalFilesDir("Pictures"))
        assertEquals(fixture.appRoot.resolve("external/data/cache"), wrapper.externalCacheDir)
        assertEquals(fixture.appRoot.resolve("obb"), wrapper.obbDir)
        assertTrue(Files.isDirectory(wrapper.noBackupFilesDir))
        assertTrue(Files.isDirectory(wrapper.codeCacheDir))

        wrapper.openFileOutput("save.dat").use { it.write("native-state".toByteArray()) }
        assertEquals("native-state", wrapper.openFileInput("save.dat").bufferedReader().use { it.readText() })
        assertEquals(listOf("save.dat"), wrapper.fileList())
        assertTrue(wrapper.deleteFile("save.dat"))
        assertFalse(wrapper.deleteFile("save.dat"))
        assertThrows(IllegalArgumentException::class.java) { wrapper.openFileOutput("../outside") }

        val preferences = wrapper.getSharedPreferences("settings")
        assertTrue(preferences.putString("theme", "dark"))
        assertTrue(preferences.putInt("launches", 7))
        assertTrue(preferences.putBoolean("enabled", true))
        assertTrue(preferences.putStringSet("tags", setOf("native", "fixture")))
        val reopenedPreferences = GuestContextWrapper(context).getSharedPreferences("settings")
        assertEquals("dark", reopenedPreferences.getString("theme"))
        assertEquals(7, reopenedPreferences.getInt("launches"))
        assertTrue(reopenedPreferences.getBoolean("enabled"))
        assertEquals(setOf("native", "fixture"), reopenedPreferences.getStringSet("tags"))
        assertThrows(ClassCastException::class.java) { reopenedPreferences.getLong("launches") }
        assertThrows(IllegalArgumentException::class.java) { wrapper.getSharedPreferences("../host") }

        assertEquals("retrobridge-test-apk", String(wrapper.readAsset("identity.txt"), Charsets.UTF_8))
        assertThrows(IllegalArgumentException::class.java) { wrapper.readAsset("../identity.txt") }
        assertThrows(java.io.FileNotFoundException::class.java) { wrapper.readAsset("missing.txt") }

        val packageInfo = wrapper.packageManager.getPackageInfo(fixture.packageName)
        assertEquals("RetroBridge Fixture", packageInfo?.applicationLabel)
        assertEquals("2.7", packageInfo?.versionName)
        assertEquals(207L, packageInfo?.versionCode)
        assertEquals(23, packageInfo?.minSdk ?: -1)
        assertEquals(35, packageInfo?.targetSdk ?: -1)
        assertNull(wrapper.packageManager.getPackageInfo("org.example.other"))
        assertThrows(IllegalArgumentException::class.java) { wrapper.externalFilesDir("../escape") }
    }

    @Test
    fun privateFileOperationsRejectSymlinkedTargets() {
        val fixture = newGuestFixture()
        val context = GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)
        val wrapper = GuestContextWrapper(context)
        val outside = Files.createTempFile("retrobridge-private-file-outside", ".txt")
        Files.write(outside, "host-owned".toByteArray())
        val symlink = wrapper.filesDir.resolve("linked.txt")
        try {
            Files.createSymbolicLink(symlink, outside)
        } catch (_: UnsupportedOperationException) {
            Files.deleteIfExists(outside)
            return
        } catch (_: java.io.IOException) {
            Files.deleteIfExists(outside)
            return
        } catch (_: SecurityException) {
            Files.deleteIfExists(outside)
            return
        }
        try {
            assertThrows(SecurityException::class.java) { wrapper.openFileInput("linked.txt") }
            assertThrows(SecurityException::class.java) {
                wrapper.openFileOutput("linked.txt").use { it.write("guest-overwrite".toByteArray()) }
            }
            assertEquals("host-owned", String(Files.readAllBytes(outside), Charsets.UTF_8))
        } finally {
            Files.deleteIfExists(symlink)
            Files.deleteIfExists(outside)
        }
    }

    @Test
    fun preferencesRejectCorruptOrSymlinkedFiles() {
        val fixture = newGuestFixture()
        val context = GuestRuntimeContextFactory.create(fixture.privateRoot, fixture.request)
        val wrapper = GuestContextWrapper(context)
        val preferencesDirectory = wrapper.sharedPreferencesDir
        val corruptFile = preferencesDirectory.resolve("corrupt.guestprefs")
        Files.write(corruptFile, byteArrayOf(1, 2, 3))
        assertThrows(java.io.IOException::class.java) {
            GuestContextWrapper(context).getSharedPreferences("corrupt")
        }

        val outside = Files.createTempFile("retrobridge-preferences-outside", ".bin")
        val symlink = preferencesDirectory.resolve("linked.guestprefs")
        try {
            Files.createSymbolicLink(symlink, outside)
        } catch (_: UnsupportedOperationException) {
            Files.deleteIfExists(outside)
            return
        } catch (_: java.io.IOException) {
            Files.deleteIfExists(outside)
            return
        } catch (_: SecurityException) {
            Files.deleteIfExists(outside)
            return
        }
        try {
            assertThrows(SecurityException::class.java) {
                GuestContextWrapper(context).getSharedPreferences("linked")
            }
        } finally {
            Files.deleteIfExists(symlink)
            Files.deleteIfExists(outside)
        }
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
        assertThrows(IllegalArgumentException::class.java) {
            GuestRuntimeContextFactory.create(
                fixture.privateRoot,
                fixture.request.copy(
                    packageMetadata = fixture.request.packageMetadata.copy(packageName = "org.example.other"),
                ),
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
        assertEquals("RUNTIME_SESSION_RUNNING", first.diagnosticEvent?.code)
        assertEquals("NATIVE_EXECUTION", first.diagnosticEvent?.operation?.name)
        val sessionId = first.sessionId ?: error("Expected an active interpreter session")

        val stopped = supervisor.stopSession(sessionId)
        assertEquals(GuestRuntimeSessionState.STOPPED, stopped.state)
        assertEquals("RUNTIME_SESSION_STOPPED", stopped.diagnosticEvent?.code)
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
        assertEquals("ARM32_LIBRARY_NOT_FOUND", result.diagnosticEvent?.code)
        assertEquals("UNSUPPORTED_ABI", result.diagnosticEvent?.category?.name)
        assertEquals(0, native.createdSessionCount)
    }

    @Test
    fun reportsTheStageAndUnsupportedOpcodeWhenExecutionStops() {
        val fixture = newGuestFixture(
            nativeLibraries = linkedMapOf(
                "lib/armeabi-v7a/libfoo.so" to byteArrayOf(1, 2, 3, 4),
                "lib/armeabi-v7a/libbar.so" to byteArrayOf(5, 6, 7, 8),
            ),
        )
        val native = FakeNativeRuntimeController().apply {
            executionDiagnostic = "unsupported T16 instruction at guest address 4096 (halfword 61440)"
        }
        val result = GuestRuntimeSessionSupervisor(fixture.privateRoot, { 200L }, native)
            .startGuestRuntimeSession(fixture.request)

        assertEquals(GuestRuntimeSessionState.FAILED, result.state)
        assertEquals("NATIVE_EXECUTION", result.diagnosticEvent?.operation?.name)
        assertEquals("UNSUPPORTED_ARM_INSTRUCTION", result.diagnosticEvent?.code)
        assertEquals("0x1000", result.diagnosticEvent?.guestAddress)
        assertEquals("0xf000", result.diagnosticEvent?.instruction)
        assertEquals(1, native.destroyedSessionCount)
    }

    @Test
    fun reportsElfInspectionFailuresAtTheCorrectStage() {
        val fixture = newGuestFixture(
            nativeLibraries = linkedMapOf("lib/armeabi-v7a/libfoo.so" to byteArrayOf(1, 2, 3, 4)),
        )
        val native = FakeNativeRuntimeController().apply { inspectionDiagnostic = "ELF class is not ELF32" }
        val result = GuestRuntimeSessionSupervisor(fixture.privateRoot, { 300L }, native)
            .startGuestRuntimeSession(fixture.request)

        assertEquals(GuestRuntimeSessionState.FAILED, result.state)
        assertEquals("ELF_INSPECTION", result.diagnosticEvent?.operation?.name)
        assertEquals("ELF_LOAD_OR_RELOCATION_FAILED", result.diagnosticEvent?.code)
        assertEquals(1, native.destroyedSessionCount)
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
                packageMetadata = GuestPackageMetadata(
                    packageName = packageName,
                    applicationLabel = "RetroBridge Fixture",
                    versionName = "2.7",
                    versionCode = 207L,
                    minSdk = 23,
                    targetSdk = 35,
                ),
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
        var inspectionDiagnostic: String? = null
        var executionDiagnostic: String? = null

        override fun createSession(context: GuestRuntimeContext): Long {
            createdSessionCount++
            return 41L
        }

        override fun inspectLibrary(sessionId: Long, libraryPath: String): NativeLibraryMetadata {
            val fileName = Path.of(libraryPath).fileName.toString()
            val dependencies = if (fileName == "libfoo.so") arrayOf("libbar.so") else emptyArray()
            val diagnostic = inspectionDiagnostic
            return NativeLibraryMetadata(diagnostic == null, fileName, fileName, dependencies, diagnostic.orEmpty())
        }

        override fun loadLibrary(sessionId: Long, libraryPath: String, expectedSha256: String): NativeLoadResult {
            val fileName = Path.of(libraryPath).fileName.toString()
            loadedFileNames += fileName
            return NativeLoadResult(true, fileName, 0x40000000L, emptyArray(), "")
        }

        override fun execute(sessionId: Long, instructionBudget: Long): NativeExecutionReport {
            val diagnostic = executionDiagnostic
            return NativeExecutionReport(
                success = diagnostic == null,
                guestInstructions = if (diagnostic == null) 123 else 0,
                relocationCount = 4,
                jniOnLoadVersion = 0x00010006,
                registeredNativeCount = 2,
                loadedLibraries = loadedFileNames.toTypedArray(),
                entrypointResults = arrayOf("libfoo.so!retrobridge_main => 7"),
                diagnostics = if (diagnostic == null) emptyArray() else arrayOf(diagnostic),
            )
        }

        override fun destroySession(sessionId: Long) {
            destroyedSessionCount++
        }
    }
}
