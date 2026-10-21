package dev.retrobridge.app

import dev.retrobridge.manager.GuestDiagnostic
import dev.retrobridge.services.RuntimeDiagnostic

internal fun RuntimeDiagnostic.toStoredDiagnostic(): GuestDiagnostic = GuestDiagnostic(
    timestampEpochMs = timestampEpochMs.coerceAtLeast(0L),
    severity = severity.name,
    component = component.take(128).ifBlank { "RetroBridge runtime" },
    message = summary.take(512).ifBlank { code },
    detail = detail?.take(4_096),
    code = code.take(64),
    category = category.name,
    operation = operation.name,
    guestId = guestId?.take(64),
    packageName = packageName?.take(255),
    library = library?.take(255),
    file = file?.take(1_024),
    symbol = symbol?.take(256),
    guestAddress = guestAddress?.take(32),
    instruction = instruction?.take(64),
    nextAction = nextAction?.take(1_024),
    occurrences = occurrences.coerceIn(1, 1_000_000),
    lastOccurredAtEpochMs = lastOccurredAtEpochMs,
)

internal fun GuestDiagnostic.toCopyableText(): String = buildString {
    appendLine("${severity.uppercase()} · $category · $code")
    appendLine("Summary: $message")
    appendLine("Component: $component · operation: $operation")
    packageName?.let { appendLine("App: $it${guestId?.let { id -> " ($id)" }.orEmpty()}") }
    library?.let { appendLine("Library: $it") }
    file?.let { appendLine("File: $it") }
    symbol?.let { appendLine("Symbol: $it") }
    guestAddress?.let { appendLine("Guest address: $it") }
    instruction?.let { appendLine("Instruction: $it") }
    appendLine("Occurrences: $occurrences")
    nextAction?.let { appendLine("Next action: $it") }
    detail?.let { appendLine("Detail: $it") }
}
