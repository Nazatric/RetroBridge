package dev.retrobridge.app

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.retrobridge.manager.GuestAppRecord
import dev.retrobridge.manager.GuestDiagnostic

@Composable
fun DiagnosticsScreen(
    modifier: Modifier = Modifier,
    events: List<GuestDiagnostic>,
    apps: List<GuestAppRecord>,
    initialGuestId: String? = null,
    storageProblem: String? = null,
    onBack: () -> Unit,
    onExport: (List<GuestDiagnostic>) -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var severityFilter by remember { mutableStateOf("ALL") }
    var categoryFilter by remember { mutableStateOf("ALL") }
    var componentFilter by remember { mutableStateOf("ALL") }
    var guestFilter by remember(initialGuestId) { mutableStateOf(initialGuestId ?: "ALL") }
    var guestMenuOpen by remember { mutableStateOf(false) }
    var componentMenuOpen by remember { mutableStateOf(false) }
    val appById = apps.associateBy(GuestAppRecord::id)
    val guestIds = (apps.map(GuestAppRecord::id) + events.mapNotNull(GuestDiagnostic::guestId)).distinct()
    val categories = listOf("ALL") + events.map(GuestDiagnostic::category).distinct().sorted()
    val components = listOf("ALL") + events.map(GuestDiagnostic::component).distinct().sorted()
    val severities = listOf("ALL", "INFO", "WARNING", "ERROR", "FATAL")
    val normalizedQuery = query.trim().lowercase()
    val visibleEvents = events
        .asSequence()
        .filter { severityFilter == "ALL" || it.severity.equals(severityFilter, ignoreCase = true) }
        .filter { categoryFilter == "ALL" || it.category == categoryFilter }
        .filter { componentFilter == "ALL" || it.component == componentFilter }
        .filter { guestFilter == "ALL" || it.guestId == guestFilter }
        .filter { event ->
            normalizedQuery.isBlank() || listOfNotNull(
                event.message,
                event.detail,
                event.code,
                event.category,
                event.component,
                event.operation,
                event.packageName,
                event.library,
                event.file,
                event.symbol,
                event.guestAddress,
                event.instruction,
                event.nextAction,
                event.guestId,
            ).any { normalizedQuery in it.lowercase() }
        }
        .sortedByDescending { it.lastOccurredAtEpochMs ?: it.timestampEpochMs }
        .toList()

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text("← Back") }
        Text("Diagnostics", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "Persisted runtime and import outcomes. Imported or preflighted does not mean launch-ready.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            "JSON exports may include package names, guest paths, symbols, and execution addresses; review before sharing.",
            style = MaterialTheme.typography.bodySmall,
        )
        storageProblem?.let { problem ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text("Diagnostic storage warning: $problem", Modifier.padding(12.dp))
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("${events.size} event group(s) · ${events.sumOf(GuestDiagnostic::occurrences)} occurrence(s)")
            Button(onClick = { onExport(visibleEvents) }, enabled = visibleEvents.isNotEmpty()) {
                Text("Export JSON")
            }
        }
        OutlinedTextField(
            value = query,
            onValueChange = { query = it.take(256) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Search diagnostics") },
            supportingText = { Text("Search code, app, library, file, symbol, address, instruction, or detail") },
        )
        Text("Severity", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            severities.forEach { value ->
                FilterChip(
                    selected = severityFilter == value,
                    onClick = { severityFilter = value },
                    label = { Text(if (value == "ALL") "All" else value.lowercase().replaceFirstChar { it.titlecase() }) },
                )
            }
        }
        Text("Category", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            categories.forEach { value ->
                FilterChip(
                    selected = categoryFilter == value,
                    onClick = { categoryFilter = value },
                    label = { Text(value.replace('_', ' ').lowercase().replaceFirstChar { it.titlecase() }) },
                )
            }
        }
        Box {
            OutlinedButton(onClick = { componentMenuOpen = true }) {
                Text("Component: ${if (componentFilter == "ALL") "All" else componentFilter}")
            }
            DropdownMenu(expanded = componentMenuOpen, onDismissRequest = { componentMenuOpen = false }) {
                components.forEach { component ->
                    DropdownMenuItem(
                        text = { Text(if (component == "ALL") "All components" else component) },
                        onClick = { componentFilter = component; componentMenuOpen = false },
                    )
                }
            }
        }
        Box {
            OutlinedButton(onClick = { guestMenuOpen = true }) {
                Text("App: ${if (guestFilter == "ALL") "All apps" else appById[guestFilter]?.displayName ?: guestFilter}")
            }
            DropdownMenu(expanded = guestMenuOpen, onDismissRequest = { guestMenuOpen = false }) {
                DropdownMenuItem(
                    text = { Text("All apps") },
                    onClick = { guestFilter = "ALL"; guestMenuOpen = false },
                )
                guestIds.forEach { id ->
                    val label = appById[id]?.displayName
                        ?: events.firstOrNull { it.guestId == id }?.packageName
                        ?: id
                    DropdownMenuItem(
                        text = { Text(label) },
                        onClick = { guestFilter = id; guestMenuOpen = false },
                    )
                }
            }
        }
        if (visibleEvents.isEmpty()) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(if (events.isEmpty()) "No diagnostics yet" else "No matching diagnostics", fontWeight = FontWeight.SemiBold)
                    Text(
                        if (events.isEmpty()) "APK preflight, import failures, and runtime attempts will be recorded here."
                        else "Change the search or filters to see other recorded events.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        } else {
            visibleEvents.forEach { event ->
                DiagnosticEventCard(event, event.guestId?.let { appById[it]?.displayName })
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun DiagnosticEventCard(event: GuestDiagnostic, appName: String?) {
    var expanded by remember(event.code, event.timestampEpochMs, event.guestId) { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text(
                "${event.severity.uppercase()} · ${event.category.replace('_', ' ')}",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.secondary,
            )
            Text(event.message, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                "${appName ?: event.packageName ?: "RetroBridge"} · ${event.component} · ${event.operation}",
                style = MaterialTheme.typography.bodySmall,
            )
            if (event.occurrences > 1) Text("Repeated ${event.occurrences} times")
            event.library?.let { Text("Library: $it", style = MaterialTheme.typography.bodySmall) }
            event.nextAction?.let { Text("Next: $it", style = MaterialTheme.typography.bodySmall) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { expanded = !expanded }) {
                    Text(if (expanded) "Hide technical detail" else "Technical detail")
                }
                TextButton(onClick = { clipboard.setText(AnnotatedString(event.toCopyableText())) }) {
                    Text("Copy")
                }
            }
            if (expanded) {
                InfoLine("Code", event.code)
                InfoLine("Operation", event.operation)
                event.packageName?.let { InfoLine("Package", it) }
                event.guestId?.let { InfoLine("Guest ID", it) }
                event.file?.let { InfoLine("File", it) }
                event.symbol?.let { InfoLine("Symbol", it) }
                event.guestAddress?.let { InfoLine("Guest address", it) }
                event.instruction?.let { InfoLine("Instruction", it) }
                event.detail?.let { InfoLine("Detail", it) }
                event.lastOccurredAtEpochMs?.let { InfoLine("Last occurrence", it.toString()) }
            }
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}
