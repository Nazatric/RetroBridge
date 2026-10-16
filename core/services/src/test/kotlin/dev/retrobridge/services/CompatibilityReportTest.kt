package dev.retrobridge.services

import org.junit.Assert.assertTrue
import org.junit.Test

class CompatibilityReportTest {
    @Test
    fun doesNotConflateElfInspectionWithGuestExecution() {
        val report = CompatibilityReport.capabilities.associateBy(Capability::name)

        assertTrue(report.getValue("ARM32 ELF metadata validation").status == CapabilityStatus.AVAILABLE)
        assertTrue(report.getValue("ARM32 / Thumb instruction execution").status == CapabilityStatus.NOT_IMPLEMENTED)
        assertTrue(report.getValue("Execution of arbitrary guest APKs").status == CapabilityStatus.NOT_IMPLEMENTED)
    }
}
