package dev.retrobridge.runtime

import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GuestRuntimeContextTest {
    @Test
    fun createsMetadataOnlyContextWithAppPrivatePathMapping() {
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
        assertFalse(context.guestCodeExecutionEnabled)
        assertTrue(GuestFrameworkCapability.APP_PRIVATE_PATH_MAPPING in context.frameworkCapabilities)
        assertTrue(context.executionUnavailableReason.contains("not loaded or executed"))
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
    fun supervisorStartsIdempotentlyAndStopsInspectionOnlySessions() {
        val fixture = newGuestFixture()
        val supervisor = GuestRuntimeSessionSupervisor(fixture.privateRoot) { 100L }

        val first = supervisor.startInspectionSession(fixture.request)
        val duplicate = supervisor.startInspectionSession(fixture.request)
        assertEquals(GuestRuntimeSessionState.INSPECTION_ONLY, first.state)
        assertEquals(first.sessionId, duplicate.sessionId)
        assertEquals(1, supervisor.activeSessionCount())
        assertFalse(first.guestCodeStarted)
        assertEquals(100L, first.startedAtEpochMs)
        val sessionId = first.sessionId ?: error("Expected an active session ID")

        val stopped = supervisor.stopSession(sessionId)
        assertEquals(GuestRuntimeSessionState.STOPPED, stopped.state)
        assertFalse(stopped.guestCodeStarted)
        assertEquals(0, supervisor.activeSessionCount())
        assertEquals(GuestRuntimeSessionState.NOT_RUNNING, supervisor.stopSession(sessionId).state)
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

    private fun newGuestFixture(): GuestFixture {
        val privateRoot = Files.createTempDirectory("retrobridge-runtime-context")
        val packageName = "org.example.runtime"
        val guestId = UUID.randomUUID().toString()
        val appRoot = privateRoot.resolve("apps/$packageName/$guestId")
        val apkPath = appRoot.resolve("app/base.apk")
        Files.createDirectories(apkPath.parent)
        Files.createDirectories(appRoot.resolve("internal/files"))
        Files.createDirectories(appRoot.resolve("external/data"))
        Files.createDirectories(appRoot.resolve("obb"))
        val apkBytes = "synthetic apk bytes".toByteArray()
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

    private data class GuestFixture(
        val privateRoot: java.nio.file.Path,
        val packageName: String,
        val guestId: String,
        val appRoot: java.nio.file.Path,
        val apkBytes: ByteArray,
        val request: GuestRuntimeContextRequest,
    )
}
