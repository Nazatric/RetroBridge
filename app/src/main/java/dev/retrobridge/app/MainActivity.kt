package dev.retrobridge.app

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import android.provider.OpenableColumns
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.retrobridge.fs.StorageBreakdown
import dev.retrobridge.manager.GuestAppRecord
import dev.retrobridge.services.Capability
import dev.retrobridge.services.CapabilityStatus
import dev.retrobridge.services.CompatibilityReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.file.Files

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val privateRoot = filesDir.toPath().resolve("RetroBridge")
        val repositoryResult = runCatching {
            Files.createDirectories(privateRoot)
            dev.retrobridge.manager.FileGuestAppRepository(privateRoot.resolve("registry.json"))
        }
        val repository = repositoryResult.getOrNull()
        val importer = repository?.let { ApkImporter(this, privateRoot, it) }
        val initialRecords = runCatching { repository?.list().orEmpty() }.getOrDefault(emptyList())
        val registryProblem = repositoryResult.exceptionOrNull()?.message

        setContent {
            MaterialTheme(
                colorScheme = lightColorScheme(
                    primary = Color(0xFF365B77),
                    secondary = Color(0xFF487C75),
                    surface = Color(0xFFF7F8FA),
                ),
            ) {
                val apps = remember {
                    mutableStateListOf<GuestAppRecord>().apply { addAll(initialRecords) }
                }
                val snackbarHostState = remember { SnackbarHostState() }
                val scope = rememberCoroutineScope()
                var selectedId by remember { mutableStateOf<String?>(null) }
                var storage by remember { mutableStateOf<StorageBreakdown?>(null) }
                var storageRefresh by remember { mutableIntStateOf(0) }
                val selected = apps.firstOrNull { it.id == selectedId }

                LaunchedEffect(selected?.id, storageRefresh) {
                    storage = null
                    if (selected != null && importer != null) {
                        storage = runCatching {
                            withContext(Dispatchers.IO) { importer.storageBreakdown(selected) }
                        }.getOrNull()
                    }
                }

                val apkPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri: Uri? ->
                    if (uri != null) {
                        scope.launch {
                            try {
                                val imported = withContext(Dispatchers.IO) {
                                    importer?.importApk(uri)
                                        ?: error("Registry is unavailable; APK import is disabled.")
                                }
                                apps.removeAll { it.id == imported.id }
                                apps.add(0, imported)
                                selectedId = imported.id
                                snackbarHostState.showSnackbar("Imported ${imported.displayName}. Guest execution is not available yet.")
                            } catch (failure: Exception) {
                                snackbarHostState.showSnackbar("Import failed: ${failure.message ?: "unknown error"}")
                            }
                        }
                    }
                }

                fun replaceRecord(record: GuestAppRecord) {
                    val index = apps.indexOfFirst { it.id == record.id }
                    if (index >= 0) apps[index] = record
                }

                val dataArchivePicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri: Uri? ->
                    val target = apps.firstOrNull { it.id == selectedId }
                    if (uri != null && target != null) {
                        scope.launch {
                            try {
                                val manager = importer ?: error("Registry is unavailable")
                                val (updated, result) = withContext(Dispatchers.IO) {
                                    val input = contentResolver.openInputStream(uri)
                                        ?: error("Unable to open the selected ZIP")
                                    input.use { manager.importDataArchive(target, it) }
                                }
                                replaceRecord(updated)
                                storageRefresh += 1
                                snackbarHostState.showSnackbar(
                                    "Imported ${result.filesImported} data files (${formatBytes(result.uncompressedBytes)}).",
                                )
                            } catch (failure: Exception) {
                                snackbarHostState.showSnackbar("Data ZIP import failed: ${failure.message ?: "unknown error"}")
                            }
                        }
                    }
                }

                val obbPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri: Uri? ->
                    val target = apps.firstOrNull { it.id == selectedId }
                    if (uri != null && target != null) {
                        scope.launch {
                            try {
                                val manager = importer ?: error("Registry is unavailable")
                                val (updated, result) = withContext(Dispatchers.IO) {
                                    val filename = queryDisplayName(uri)
                                    val input = contentResolver.openInputStream(uri)
                                        ?: error("Unable to open the selected OBB")
                                    input.use {
                                        if (filename.endsWith(".zip", ignoreCase = true)) {
                                            manager.importObbBundle(target, it)
                                        } else {
                                            manager.importObbFile(target, filename, it)
                                        }
                                    }
                                }
                                replaceRecord(updated)
                                storageRefresh += 1
                                snackbarHostState.showSnackbar(
                                    "Imported ${result.paths.size} OBB file(s) (${formatBytes(result.bytesImported)}).",
                                )
                            } catch (failure: Exception) {
                                snackbarHostState.showSnackbar("OBB import failed: ${failure.message ?: "unknown error"}")
                            }
                        }
                    }
                }

                val exportPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.CreateDocument("application/zip"),
                ) { uri: Uri? ->
                    val target = apps.firstOrNull { it.id == selectedId }
                    if (uri != null && target != null) {
                        scope.launch {
                            try {
                                val manager = importer ?: error("Registry is unavailable")
                                val result = withContext(Dispatchers.IO) {
                                    val output = contentResolver.openOutputStream(uri)
                                        ?: error("Unable to create the destination ZIP")
                                    output.use { manager.exportGuestData(target, it) }
                                }
                                snackbarHostState.showSnackbar(
                                    "Exported ${result.filesExported} files (${formatBytes(result.bytesExported)}).",
                                )
                            } catch (failure: Exception) {
                                snackbarHostState.showSnackbar("Export failed: ${failure.message ?: "unknown error"}")
                            }
                        }
                    }
                }

                Scaffold(snackbarHost = { SnackbarHost(snackbarHostState) }) { padding ->
                    if (selected == null) {
                        AppListScreen(
                            modifier = Modifier.padding(padding),
                            apps = apps,
                            registryProblem = registryProblem,
                            onImport = {
                                if (importer == null) {
                                    scope.launch {
                                        snackbarHostState.showSnackbar("Registry is unavailable; inspect the diagnostic shown below.")
                                    }
                                } else {
                                    apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "*/*"))
                                }
                            },
                            onSelect = { selectedId = it.id },
                        )
                    } else {
                        AppDetailsScreen(
                            modifier = Modifier.padding(padding),
                            record = selected,
                            storage = storage,
                            onBack = { selectedId = null },
                            onAttachData = {
                                dataArchivePicker.launch(arrayOf("application/zip", "application/x-zip-compressed", "*/*"))
                            },
                            onAttachObb = {
                                obbPicker.launch(arrayOf("application/octet-stream", "application/zip", "*/*"))
                            },
                            onExport = {
                                exportPicker.launch("${selected.packageName}-retrobridge-data.zip")
                            },
                            onClearData = {
                                scope.launch {
                                    try {
                                        withContext(Dispatchers.IO) {
                                            importer?.clearData(selected) ?: error("Registry is unavailable")
                                        }
                                        storageRefresh += 1
                                        snackbarHostState.showSnackbar("Cleared guest-owned data. The imported APK and OBB files were retained.")
                                    } catch (failure: Exception) {
                                        snackbarHostState.showSnackbar("Clear Data failed: ${failure.message ?: "unknown error"}")
                                    }
                                }
                            },
                            onRemove = {
                                scope.launch {
                                    try {
                                        withContext(Dispatchers.IO) {
                                            importer?.remove(selected) ?: error("Registry is unavailable")
                                        }
                                        apps.removeAll { it.id == selected.id }
                                        selectedId = null
                                        storage = null
                                        snackbarHostState.showSnackbar("Removed ${selected.displayName} from RetroBridge.")
                                    } catch (failure: Exception) {
                                        snackbarHostState.showSnackbar("Remove failed: ${failure.message ?: "unknown error"}")
                                    }
                                }
                            },
                        )
                    }
                }
            }
        }
    }

    private fun queryDisplayName(uri: Uri): String {
        val cursor = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        if (cursor != null) {
            cursor.use {
                if (it.moveToFirst()) {
                    val column = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (column >= 0) it.getString(column)?.takeIf(String::isNotBlank)?.let { name -> return name }
                }
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/')?.substringAfterLast(':') ?: "selected.obb"
    }
}

@androidx.compose.runtime.Composable
private fun AppListScreen(
    modifier: Modifier,
    apps: List<GuestAppRecord>,
    registryProblem: String?,
    onImport: () -> Unit,
    onSelect: (GuestAppRecord) -> Unit,
) {
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("RetroBridge", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("ARM32 compatibility runtime · experimental prototype", style = MaterialTheme.typography.bodyMedium)
        WarningCard(
            title = "Guest execution is not implemented",
            body = "RetroBridge can import and inspect APK metadata, but it cannot launch 32-bit apps. ARM instruction translation, the guest linker/Bionic, JNI, and framework services are not yet available.",
        )
        if (registryProblem != null) {
            WarningCard("Registry could not be opened", registryProblem)
        }
        Button(onClick = onImport, modifier = Modifier.fillMaxWidth()) {
            Text("Import APK")
        }
        Text("Imported applications (${apps.size})", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        if (apps.isEmpty()) {
            Text("No APKs imported. Choose a single APK to copy it into RetroBridge's private app storage.")
        } else {
            apps.forEach { record ->
                Card(
                    modifier = Modifier.fillMaxWidth().clickable { onSelect(record) },
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(record.displayName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(record.packageName, style = MaterialTheme.typography.bodySmall)
                        Text("State: ${record.state.name.lowercase()} · ABI: ${record.guestAbis.joinToString().ifBlank { "no bundled native ABI detected" }}")
                    }
                }
            }
        }
        HorizontalDivider()
        Text("Current compatibility", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        CompatibilityReport.capabilities.forEach { CapabilityRow(it) }
    }
}

@androidx.compose.runtime.Composable
private fun AppDetailsScreen(
    modifier: Modifier,
    record: GuestAppRecord,
    storage: StorageBreakdown?,
    onBack: () -> Unit,
    onAttachData: () -> Unit,
    onAttachObb: () -> Unit,
    onExport: () -> Unit,
    onClearData: () -> Unit,
    onRemove: () -> Unit,
) {
    var pendingAction by remember(record.id) { mutableStateOf<PendingAction?>(null) }
    if (pendingAction != null) {
        val action = pendingAction!!
        AlertDialog(
            onDismissRequest = { pendingAction = null },
            title = { Text(if (action == PendingAction.CLEAR_DATA) "Clear guest data?" else "Remove imported app?") },
            text = {
                Text(
                    if (action == PendingAction.CLEAR_DATA) {
                        "This deletes this app's internal and app-specific external data. The imported APK and OBB files will be retained."
                    } else {
                        "This permanently deletes only ${record.packageName}'s RetroBridge files and registry entry."
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingAction = null
                    if (action == PendingAction.CLEAR_DATA) onClearData() else onRemove()
                }) { Text(if (action == PendingAction.CLEAR_DATA) "Clear" else "Remove") }
            },
            dismissButton = { TextButton(onClick = { pendingAction = null }) { Text("Cancel") } },
        )
    }

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text("← All applications") }
        Text(record.displayName, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        InfoRow("Package", record.packageName)
        InfoRow("Version", "${record.versionName ?: "unknown"} (${record.versionCode})")
        InfoRow("SDK range", "min ${record.minSdk ?: "unknown"} · target ${record.targetSdk ?: "unknown"}")
        InfoRow("Guest ABI(s)", record.guestAbis.joinToString().ifBlank { "No bundled native libraries detected" })
        InfoRow(
            "Bundled native libraries",
            record.nativeLibraries.toSortedMap().entries.joinToString("; ") { (abi, names) -> "$abi: ${names.joinToString()}" }
                .ifBlank { "None detected" },
        )
        InfoRow("Lifecycle", record.state.name.lowercase())
        InfoRow("APK SHA-256", record.sha256)
        InfoRow("Private APK path", record.originalApkPath)
        InfoRow("Split APKs", record.splitApkPaths.joinToString().ifBlank { "None" })
        InfoRow("Android/data archive", record.dataArchiveState.name.lowercase())
        InfoRow("OBB", "${record.obbState.name.lowercase()} · ${record.obbFiles.joinToString().ifBlank { "no files" }}")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onAttachData) { Text("Attach data ZIP") }
            OutlinedButton(onClick = onAttachObb) { Text("Attach OBB / ZIP") }
        }

        HorizontalDivider()
        Text("Storage", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        if (storage == null) {
            Text("Storage usage is unavailable or still being measured.")
        } else {
            InfoRow("APK and metadata", formatBytes(storage.apkAndMetadataBytes))
            InfoRow("Internal files", formatBytes(storage.internalBytes))
            InfoRow("External app data", formatBytes(storage.externalBytes))
            InfoRow("OBB", formatBytes(storage.obbBytes))
            InfoRow("Shared files", formatBytes(storage.sharedBytes))
            InfoRow("Total", formatBytes(storage.totalBytes))
        }

        HorizontalDivider()
        Text("Runtime settings", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        if (record.compatibilityOverrides.values.isEmpty()) {
            Text("No per-app compatibility overrides.")
        } else {
            record.compatibilityOverrides.values.toSortedMap().forEach { (key, value) -> InfoRow(key, value) }
        }

        HorizontalDivider()
        Text("Compatibility report", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        CompatibilityReport.capabilities.forEach { CapabilityRow(it) }

        HorizontalDivider()
        Text("Recent diagnostics", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        InfoRow("Crash dumps", record.crashDumpPaths.joinToString().ifBlank { "None" })
        if (record.diagnostics.isEmpty()) {
            Text("No diagnostics recorded.")
        } else {
            record.diagnostics.takeLast(10).reversed().forEach { diagnostic ->
                Text("${diagnostic.severity.uppercase()} · ${diagnostic.component}: ${diagnostic.message}")
                diagnostic.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }

        HorizontalDivider()
        Text("Lifecycle actions", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {}, enabled = false) { Text("Launch") }
            OutlinedButton(onClick = {}, enabled = false) { Text("Stop") }
            OutlinedButton(onClick = onExport) { Text("Export data ZIP") }
        }
        Text("Launch and Stop remain disabled because arbitrary Android framework execution is not yet supported.", style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { pendingAction = PendingAction.CLEAR_DATA }) { Text("Clear Data") }
            OutlinedButton(onClick = { pendingAction = PendingAction.REMOVE }) { Text("Remove") }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@androidx.compose.runtime.Composable
private fun WarningCard(title: String, body: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF2DA))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(body)
        }
    }
}

@androidx.compose.runtime.Composable
private fun CapabilityRow(capability: Capability) {
    Column(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text("${capability.status.label()} · ${capability.name}", fontWeight = FontWeight.SemiBold)
        Text(capability.explanation, style = MaterialTheme.typography.bodySmall)
    }
}

@androidx.compose.runtime.Composable
private fun InfoRow(label: String, value: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

private fun CapabilityStatus.label(): String = when (this) {
    CapabilityStatus.AVAILABLE -> "Available"
    CapabilityStatus.PARTIAL -> "Partial"
    CapabilityStatus.NOT_IMPLEMENTED -> "Not implemented"
    CapabilityStatus.REQUIRES_PRIVILEGED_INTEGRATION -> "Privileged integration"
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = listOf("KiB", "MiB", "GiB", "TiB")
    var amount = bytes.toDouble()
    var unit = -1
    do {
        amount /= 1024.0
        unit += 1
    } while (amount >= 1024.0 && unit < units.lastIndex)
    return "%.1f %s".format(amount, units[unit])
}

private enum class PendingAction { CLEAR_DATA, REMOVE }
