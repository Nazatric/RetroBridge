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
            CapabilityStatus.PARTIAL,
            report.getValue("Headless ANativeWindow buffer subset").status,
        )
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("Synthetic AInputQueue and ALooper subset").status,
        )
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("Headless EGL/GLES clear subset").status,
        )
        assertEquals(
            CapabilityStatus.NOT_IMPLEMENTED,
            report.getValue("Execution of arbitrary guest APKs").status,
        )
        assertTrue(report.getValue("Execution of arbitrary guest APKs").explanation.contains("not a guest-app launch"))
    }

    @Test
    fun reportsOpenSlAndInspectionOnlyRuntimeAsPartial() {
        val report = CompatibilityReport.capabilities.associateBy(Capability::name)

        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("OpenSL ES PCM buffer-queue subset").status,
        )
        assertTrue(report.getValue("OpenSL ES PCM buffer-queue subset").explanation.contains("no Android audio sink"))
        assertEquals(
            CapabilityStatus.PARTIAL,
            report.getValue("Guest IPC and Android framework virtualization").status,
        )
        assertTrue(
            report.getValue("Guest IPC and Android framework virtualization").explanation.contains("never loads guest code"),
        )
    }
}
