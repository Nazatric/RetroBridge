package dev.retrobridge.app

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.retrobridge.manager.FileGuestAppRepository
import dev.retrobridge.runtime.GuestRuntimeProtocol
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class GuestRuntimeDemoInstrumentedTest {
    @Test
    fun importsSignedDemoApkExecutesGuestCodeAndRunsDestructorOnStop() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val targetContext = instrumentation.targetContext
        val privateRoot = targetContext.filesDir.toPath().resolve("RetroBridge")
        val demoApk = targetContext.cacheDir.toPath().resolve("retrobridge-runtime-demo.apk")
        instrumentation.context.assets.open(DEMO_APK_ASSET).use { input ->
            Files.copy(input, demoApk, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }

        val repository = FileGuestAppRepository(privateRoot.resolve("guest-apps.json"))
        val importer = ApkImporter(targetContext, privateRoot, repository)
        val record = importer.importApk(Uri.fromFile(demoApk.toFile()))
        assertEquals(DEMO_PACKAGE, record.packageName)
        assertTrue(record.guestAbis.contains("armeabi-v7a"))
        assertTrue(record.nativeLibraries["armeabi-v7a"].orEmpty().any { it.endsWith("libretrobridge_demo.so") })

        val appRoot = privateRoot.resolve(record.isolatedRoot)
        val output = appRoot.resolve("internal/files/native-demo.txt")
        val client = GuestRuntimeClient(targetContext)
        try {
            val launched = client.launchGuestRuntime(record)
            assertEquals(GuestRuntimeProtocol.STATE_RUNNING, launched.state)
            assertTrue("Expected machine-code execution: ${launched.diagnostic}", launched.guestCodeStarted)
            assertTrue("Expected a nonzero guest instruction count", launched.guestInstructions > 0L)
            assertEquals("RUNTIME_SESSION_RUNNING", launched.diagnosticEvent?.code)
            assertEquals("NATIVE_EXECUTION", launched.diagnosticEvent?.operation?.name)
            assertTrue("Expected ELF relocations", launched.relocationCount > 0)
            assertEquals(0x00010006, launched.jniOnLoadVersion)
            assertTrue(launched.loadedLibraries.any { it.contains("libretrobridge_demo.so") })
            assertTrue(launched.entrypointResults.any { it.contains("retrobridge_main => 42") })

            val runningOutput = String(Files.readAllBytes(output), Charsets.UTF_8)
            assertTrue(runningOutput.contains("constructor\n"))
            assertTrue(runningOutput.contains("JNI_OnLoad\n"))
            assertTrue(runningOutput.contains("entrypoint\n"))
            assertFalse(runningOutput.contains("math-failed"))
            assertTrue(runningOutput.indexOf("constructor\n") < runningOutput.indexOf("JNI_OnLoad\n"))
            assertTrue(runningOutput.indexOf("JNI_OnLoad\n") < runningOutput.indexOf("entrypoint\n"))

            val sessionId = launched.sessionId
            assertNotNull("Expected an active service-owned session", sessionId)
            val stopped = client.stopSession(requireNotNull(sessionId))
            assertEquals(GuestRuntimeProtocol.STATE_STOPPED, stopped.state)
            assertEquals("RUNTIME_SESSION_STOPPED", stopped.diagnosticEvent?.code)
            assertTrue(stopped.guestCodeStarted)
            assertTrue(stopped.diagnostic.contains("destructors", ignoreCase = true))

            val stoppedOutput = String(Files.readAllBytes(output), Charsets.UTF_8)
            assertTrue(stoppedOutput.endsWith("destructor\n"))
            assertTrue(stoppedOutput.indexOf("entrypoint\n") < stoppedOutput.indexOf("destructor\n"))
        } finally {
            client.close()
            importer.remove(record)
            Files.deleteIfExists(demoApk)
        }
    }

    private companion object {
        const val DEMO_APK_ASSET = "guestdemo.apk"
        const val DEMO_PACKAGE = "org.retrobridge.guestdemo"
    }
}
