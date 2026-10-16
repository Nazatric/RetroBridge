package dev.retrobridge.services

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CompatibilityReportTest {
    @Test
    fun keepsImplementedSlicesPartialAndDoesNotClaimApkLaunch() {
        val report = CompatibilityReport.capabilities.associateBy(Capability::name)

        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("APK metadata import and native-library preflight").status,
        )
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("ARM32 / Thumb instruction execution").status,
        )
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("Guest heap, VFS, and ARM EABI syscalls").status,
        )
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("JNI and JavaVM").status,
        )
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("NDK AAssetManager/AAsset subset").status,
        )
        assertEquals(
            CapabilityStatus.NOT_IMPLEMENTED,
            report.getValue("Execution of arbitrary guest APKs").status,
        )
        assertTrue(report.getValue("Execution of arbitrary guest APKs").explanation.contains("not functional"))
    }

    @Test
    fun marksNdkGraphicsAudioAndFrameworkBridgesUnavailable() {
        val report = CompatibilityReport.capabilities.associateBy(Capability::name)

        listOf(
            "ANativeWindow and Android input",
            "Headless GLES/EGL",
            "OpenSL ES audio",
            "Guest IPC and Android framework virtualization",
        ).forEach { name ->
            assertEquals(name, CapabilityStatus.NOT_IMPLEMENTED, report.getValue(name).status)
        }
    }
}
