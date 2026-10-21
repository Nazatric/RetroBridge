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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.retrobridge.fs.StorageBreakdown
import dev.retrobridge.manager.FileGuestDiagnosticRepository
import dev.retrobridge.manager.GuestAppRecord
import dev.retrobridge.manager.GuestDiagnostic
import dev.retrobridge.manager.GuestDiagnosticJson
import dev.retrobridge.manager.LaunchRecord
import dev.retrobridge.services.Capability
import dev.retrobridge.services.CapabilityStatus
import dev.retrobridge.services.CompatibilityReport
import dev.retrobridge.services.DiagnosticCategory
import dev.retrobridge.services.DiagnosticOperation
import dev.retrobridge.services.DiagnosticSeverity
import dev.retrobridge.services.RuntimeDiagnostic
import dev.retrobridge.services.RuntimeDiagnosticClassifier
import dev.retrobridge.runtime.GuestRuntimeProtocol
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import java.nio.file.Files

class MainActivity : ComponentActivity() {
    private lateinit var runtimeClient: GuestRuntimeClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtimeClient = GuestRuntimeClient(this)

        val privateRoot = filesDir.toPath().resolve("RetroBridge")
        val repositoryResult = runCatching {
            Files.createDirectories(privateRoot)
            dev.retrobridge.manager.FileGuestAppRepository(privateRoot.resolve("registry.json")).let { repo ->
                repo to repo.list()
            }
        }
        val repository = repositoryResult.getOrNull()?.first
        val importer = repository?.let { ApkImporter(this, privateRoot, it) }
        val initialRecords = repositoryResult.getOrNull()?.second.orEmpty()
        val registryProblem = repositoryResult.exceptionOrNull()?.let { it.message ?: it.javaClass.simpleName }
        val diagnosticRepositoryResult = runCatching {
            Files.createDirectories(privateRoot)
            FileGuestDiagnosticRepository(privateRoot.resolve("diagnostics.json"))
        }
        val diagnosticRepository = diagnosticRepositoryResult.getOrNull()
        val diagnosticLoadResult = runCatching { diagnosticRepository?.list().orEmpty() }
        val initialDiagnosticEvents = diagnosticLoadResult.getOrDefault(emptyList())
        val diagnosticStoreProblem = diagnosticRepositoryResult.exceptionOrNull()?.let {
            (it.message ?: it.javaClass.simpleName).take(512)
        } ?: diagnosticLoadResult.exceptionOrNull()?.let { (it.message ?: it.javaClass.simpleName).take(512) }
            ?: if (diagnosticRepository == null) "Diagnostic history is unavailable; new events will be kept only in memory." else null

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
                val diagnosticEvents = remember {
                    mutableStateListOf<GuestDiagnostic>().apply { addAll(initialDiagnosticEvents) }
                }
                val pendingDiagnosticEvents = remember { mutableListOf<GuestDiagnostic>() }
                val diagnosticWriteMutex = remember { Mutex() }
                val snackbarHostState = remember { SnackbarHostState() }
                val scope = rememberCoroutineScope()
                val runtimeSessions = remember { mutableStateMapOf<String, RuntimeSessionUi>() }
                var operationBusy by remember { mutableStateOf(false) }
                var selectedId by remember { mutableStateOf<String?>(null) }
                var diagnosticsOpen by remember { mutableStateOf(false) }
                var diagnosticsGuestFilter by remember { mutableStateOf<String?>(null) }
                var diagnosticExportSnapshot by remember { mutableStateOf(emptyList<GuestDiagnostic>()) }
                var diagnosticStorageProblem by remember { mutableStateOf(diagnosticStoreProblem) }
                var storage by remember { mutableStateOf<StorageBreakdown?>(null) }
                var storageRefresh by remember { mutableIntStateOf(0) }
                val selected = apps.firstOrNull { it.id == selectedId }

                suspend fun showOperationResult(message: String) {
                    operationBusy = false
                    snackbarHostState.showSnackbar(message)
                }

                suspend fun recordDiagnostic(event: GuestDiagnostic) {
                    diagnosticWriteMutex.lock()
                    try {
                        val pending = pendingDiagnosticEvents.toList()
                        val unavailableReason = diagnosticStorageProblem
                        val saved = try {
                            withContext(Dispatchers.IO) {
                                val store = diagnosticRepository
                                    ?: throw IllegalStateException(unavailableReason ?: "Diagnostic history is unavailable")
                                store.appendAll(pending + event)
                            }
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            diagnosticStorageProblem = (failure.message ?: failure.javaClass.simpleName).take(512)
                            pendingDiagnosticEvents.add(event)
                            diagnosticEvents.add(event)
                            while (diagnosticEvents.size > 500) diagnosticEvents.removeAt(0)
                            while (pendingDiagnosticEvents.size > 500) pendingDiagnosticEvents.removeAt(0)
                            return
                        }
                        pendingDiagnosticEvents.clear()
                        diagnosticEvents.clear()
                        diagnosticEvents.addAll(saved)
                        diagnosticStorageProblem = null
                    } finally {
                        diagnosticWriteMutex.unlock()
                    }
                }

                LaunchedEffect(selected?.id, storageRefresh) {
                    storage = null
                    if (selected != null && importer != null) {
                        storage = try {
                            withContext(Dispatchers.IO) { importer.storageBreakdown(selected) }
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (_: Exception) {
                            null
                        }
                    }
                }

                val apkPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri: Uri? ->
                    if (uri != null && !operationBusy) {
                        operationBusy = true
                        scope.launch {
                            try {
                                val imported = withContext(Dispatchers.IO) {
                                    importer?.importApk(uri)
                                        ?: error("Registry is unavailable; APK import is disabled.")
                                }
                                apps.removeAll { it.id == imported.id }
                                apps.add(0, imported)
                                selectedId = imported.id
                                recordDiagnostic(apkImportedDiagnostic(imported).toStoredDiagnostic())
                                showOperationResult("Imported ${imported.displayName}. Native launchability is not established by import or preflight.")
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (failure: Exception) {
                                val event = RuntimeDiagnosticClassifier.failure(
                                    operation = DiagnosticOperation.APK_IMPORT,
                                    message = failure.message ?: failure.javaClass.simpleName,
                                    exceptionType = failure.javaClass.name,
                                )
                                recordDiagnostic(event.toStoredDiagnostic())
                                showOperationResult(event.summary)
                            } finally {
                                operationBusy = false
                            }
                        }
                    }
                }

                fun replaceRecord(record: GuestAppRecord) {
                    val index = apps.indexOfFirst { it.id == record.id }
                    if (index >= 0) apps[index] = record
                }

                suspend fun persistLaunchOutcome(
                    target: GuestAppRecord,
                    state: String,
                    startedAtEpochMs: Long,
                    event: GuestDiagnostic,
                ) {
                    val store = repository ?: return
                    try {
                        val updated = withContext(Dispatchers.IO) {
                            store.update(target.id) { current ->
                                val now = maxOf(event.timestampEpochMs, current.updatedAtEpochMs)
                                val outcome = if (state == GuestRuntimeProtocol.STATE_RUNNING) {
                                    "NATIVE_ENTRYPOINTS_COMPLETED"
                                } else {
                                    state
                                }
                                val history = current.launchHistory + LaunchRecord(
                                    startedAtEpochMs = startedAtEpochMs.takeIf { it > 0L } ?: now,
                                    endedAtEpochMs = now,
                                    outcome = outcome,
                                    diagnostic = event.message,
                                )
                                current.copy(
                                    launchHistory = history.takeLast(200),
                                    updatedAtEpochMs = now,
                                )
                            }
                        }
                        replaceRecord(updated)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (failure: Exception) {
                        diagnosticStorageProblem = (failure.message ?: failure.javaClass.simpleName).take(512)
                    }
                }

                fun startRuntimeSession(target: GuestAppRecord) {
                    if (operationBusy || runtimeSessions[target.id]?.sessionId != null) return
                    operationBusy = true
                    scope.launch {
                        try {
                            val result = runtimeClient.launchGuestRuntime(target)
                            runtimeSessions[target.id] = RuntimeSessionUi.from(result)
                            val event = result.diagnosticEvent ?: if (result.state == GuestRuntimeProtocol.STATE_RUNNING) {
                                RuntimeDiagnosticClassifier.sessionRunning(
                                    guestId = target.id,
                                    packageName = target.packageName,
                                    timestampEpochMs = result.startedAtEpochMs,
                                    instructions = result.guestInstructions,
                                    libraries = result.loadedLibraries,
                                )
                            } else {
                                RuntimeDiagnosticClassifier.failure(
                                    operation = DiagnosticOperation.NATIVE_EXECUTION,
                                    message = result.diagnostic,
                                    guestId = target.id,
                                    packageName = target.packageName,
                                )
                            }
                            val storedEvent = event.toStoredDiagnostic()
                            recordDiagnostic(storedEvent)
                            persistLaunchOutcome(target, result.state, result.startedAtEpochMs, storedEvent)
                            if (result.state != GuestRuntimeProtocol.STATE_RUNNING || result.sessionId == null) {
                                showOperationResult(event.summary)
                            } else {
                                showOperationResult(
                                    "Selected ARM32 native entrypoints completed (${result.guestInstructions} instructions). This does not verify full APK/game compatibility.",
                                )
                            }
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            val event = RuntimeDiagnosticClassifier.failure(
                                operation = DiagnosticOperation.IPC,
                                message = failure.message ?: failure.javaClass.simpleName,
                                guestId = target.id,
                                packageName = target.packageName,
                                exceptionType = failure.javaClass.name,
                            )
                            val storedEvent = event.toStoredDiagnostic()
                            recordDiagnostic(storedEvent)
                            persistLaunchOutcome(target, GuestRuntimeProtocol.STATE_FAILED, 0L, storedEvent)
                            showOperationResult(event.summary)
                        } finally {
                            operationBusy = false
                        }
                    }
                }

                fun stopRuntimeSession(target: GuestAppRecord) {
                    val current = runtimeSessions[target.id] ?: return
                    val sessionId = current.sessionId ?: return
                    if (operationBusy) return
                    operationBusy = true
                    scope.launch {
                        try {
                            val result = runtimeClient.stopSession(sessionId)
                            if (result.state == GuestRuntimeProtocol.STATE_STOPPED ||
                                result.state == GuestRuntimeProtocol.STATE_NOT_RUNNING
                            ) {
                                runtimeSessions.remove(target.id)
                            }
                            val event = result.diagnosticEvent ?: RuntimeDiagnosticClassifier.failure(
                                operation = DiagnosticOperation.RUNTIME_STOP,
                                message = result.diagnostic,
                                guestId = target.id,
                                packageName = target.packageName,
                            )
                            val storedEvent = event.toStoredDiagnostic()
                            recordDiagnostic(storedEvent)
                            persistLaunchOutcome(target, result.state, result.startedAtEpochMs, storedEvent)
                            showOperationResult(event.summary)
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            val event = RuntimeDiagnosticClassifier.failure(
                                operation = DiagnosticOperation.RUNTIME_STOP,
                                message = failure.message ?: failure.javaClass.simpleName,
                                guestId = target.id,
                                packageName = target.packageName,
                                exceptionType = failure.javaClass.name,
                            )
                            val storedEvent = event.toStoredDiagnostic()
                            recordDiagnostic(storedEvent)
                            showOperationResult(event.summary)
                        } finally {
                            operationBusy = false
                        }
                    }
                }

                suspend fun stopRuntimeSessionBeforeStorageChange(target: GuestAppRecord) {
                    val current = runtimeSessions[target.id] ?: return
                    val reply = stopRuntimeSessionForStorageChange(
                        current.sessionId,
                        current.state,
                        runtimeClient::stopSession,
                    )
                    runtimeSessions.remove(target.id)
                    if (reply != null) {
                        val event = reply.diagnosticEvent ?: if (reply.state == GuestRuntimeProtocol.STATE_STOPPED) {
                            RuntimeDiagnosticClassifier.sessionStopped(
                                guestId = target.id,
                                packageName = target.packageName,
                                timestampEpochMs = System.currentTimeMillis(),
                                detail = reply.diagnostic,
                            )
                        } else {
                            RuntimeDiagnosticClassifier.sessionNotFound(System.currentTimeMillis())
                        }
                        val storedEvent = event.toStoredDiagnostic()
                        recordDiagnostic(storedEvent)
                        persistLaunchOutcome(target, reply.state, reply.startedAtEpochMs, storedEvent)
                    }
                }

                val dataArchivePicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri: Uri? ->
                    val target = apps.firstOrNull { it.id == selectedId }
                    if (uri != null && target != null && !operationBusy) {
                        operationBusy = true
                        scope.launch {
                            try {
                                stopRuntimeSessionBeforeStorageChange(target)
                                val manager = importer ?: error("Registry is unavailable")
                                val (updated, result) = withContext(Dispatchers.IO) {
                                    val input = contentResolver.openInputStream(uri)
                                        ?: error("Unable to open the selected ZIP")
                                    input.use { manager.importDataArchive(target, it) }
                                }
                                replaceRecord(updated)
                                storageRefresh += 1
                                recordDiagnostic(
                                    storageDiagnostic(
                                        target,
                                        DiagnosticOperation.DATA_IMPORT,
                                        "DATA_ARCHIVE_IMPORTED",
                                        "App data archive imported.",
                                        "${result.filesImported} files; ${result.uncompressedBytes} uncompressed bytes.",
                                    ).toStoredDiagnostic(),
                                )
                                showOperationResult(
                                    "Imported ${result.filesImported} data files (${formatBytes(result.uncompressedBytes)}).",
                                )
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (failure: Exception) {
                                val event = RuntimeDiagnosticClassifier.failure(
                                    DiagnosticOperation.DATA_IMPORT,
                                    failure.message ?: failure.javaClass.simpleName,
                                    guestId = target.id,
                                    packageName = target.packageName,
                                    exceptionType = failure.javaClass.name,
                                )
                                recordDiagnostic(event.toStoredDiagnostic())
                                showOperationResult(event.summary)
                            } finally {
                                operationBusy = false
                            }
                        }
                    }
                }

                val obbPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri: Uri? ->
                    val target = apps.firstOrNull { it.id == selectedId }
                    if (uri != null && target != null && !operationBusy) {
                        operationBusy = true
                        scope.launch {
                            try {
                                stopRuntimeSessionBeforeStorageChange(target)
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
                                recordDiagnostic(
                                    storageDiagnostic(
                                        target,
                                        DiagnosticOperation.OBB_IMPORT,
                                        "OBB_CONTENT_IMPORTED",
                                        "OBB content imported into app-private storage.",
                                        "${result.paths.size} file(s); ${result.bytesImported} bytes.",
                                    ).toStoredDiagnostic(),
                                )
                                showOperationResult(
                                    "Imported ${result.paths.size} OBB file(s) (${formatBytes(result.bytesImported)}).",
                                )
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (failure: Exception) {
                                val event = RuntimeDiagnosticClassifier.failure(
                                    DiagnosticOperation.OBB_IMPORT,
                                    failure.message ?: failure.javaClass.simpleName,
                                    guestId = target.id,
                                    packageName = target.packageName,
                                    exceptionType = failure.javaClass.name,
                                )
                                recordDiagnostic(event.toStoredDiagnostic())
                                showOperationResult(event.summary)
                            } finally {
                                operationBusy = false
                            }
                        }
                    }
                }

                val exportPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.CreateDocument("application/zip"),
                ) { uri: Uri? ->
                    val target = apps.firstOrNull { it.id == selectedId }
                    if (uri != null && target != null && !operationBusy) {
                        operationBusy = true
                        scope.launch {
                            try {
                                stopRuntimeSessionBeforeStorageChange(target)
                                val manager = importer ?: error("Registry is unavailable")
                                val result = withContext(Dispatchers.IO) {
                                    val output = contentResolver.openOutputStream(uri)
                                        ?: error("Unable to create the destination ZIP")
                                    output.use { manager.exportGuestData(target, it) }
                                }
                                recordDiagnostic(
                                    storageDiagnostic(
                                        target,
                                        DiagnosticOperation.DATA_EXPORT,
                                        "DATA_EXPORT_COMPLETED",
                                        "Guest data export completed.",
                                        "${result.filesExported} file(s); ${result.bytesExported} bytes.",
                                    ).toStoredDiagnostic(),
                                )
                                showOperationResult(
                                    "Exported ${result.filesExported} files (${formatBytes(result.bytesExported)}).",
                                )
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (failure: Exception) {
                                val event = RuntimeDiagnosticClassifier.failure(
                                    DiagnosticOperation.DATA_EXPORT,
                                    failure.message ?: failure.javaClass.simpleName,
                                    guestId = target.id,
                                    packageName = target.packageName,
                                    exceptionType = failure.javaClass.name,
                                )
                                recordDiagnostic(event.toStoredDiagnostic())
                                showOperationResult(event.summary)
                            } finally {
                                operationBusy = false
                            }
                        }
                    }
                }

                val diagnosticExportPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.CreateDocument("application/json"),
                ) { uri: Uri? ->
                    if (uri != null) scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                val output = contentResolver.openOutputStream(uri)
                                    ?: error("Unable to create the diagnostic report")
                                output.use { it.write(GuestDiagnosticJson.encode(diagnosticExportSnapshot).toByteArray(Charsets.UTF_8)) }
                            }
                            showOperationResult("Exported ${diagnosticExportSnapshot.size} diagnostic event group(s) as JSON.")
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            val event = RuntimeDiagnosticClassifier.failure(
                                DiagnosticOperation.DIAGNOSTIC_EXPORT,
                                failure.message ?: failure.javaClass.simpleName,
                                exceptionType = failure.javaClass.name,
                            )
                            recordDiagnostic(event.toStoredDiagnostic())
                            showOperationResult(event.summary)
                        }
                    }
                }

                Scaffold(snackbarHost = { SnackbarHost(snackbarHostState) }) { padding ->
                    val combinedDiagnostics = (diagnosticEvents.toList() + apps.flatMap(GuestAppRecord::diagnostics)).distinct()
                    if (diagnosticsOpen) {
                        DiagnosticsScreen(
                            modifier = Modifier.padding(padding),
                            events = combinedDiagnostics,
                            apps = apps,
                            initialGuestId = diagnosticsGuestFilter,
                            storageProblem = diagnosticStorageProblem,
                            onBack = { diagnosticsOpen = false },
                            onExport = { snapshot ->
                                diagnosticExportSnapshot = snapshot.toList()
                                diagnosticExportPicker.launch("retrobridge-diagnostics.json")
                            },
                        )
                    } else if (selected == null) {
                        AppListScreen(
                            modifier = Modifier.padding(padding),
                            apps = apps,
                            registryProblem = registryProblem,
                            diagnosticCount = combinedDiagnostics.size,
                            canImport = importer != null,
                            operationBusy = operationBusy,
                            onDiagnostics = {
                                diagnosticsGuestFilter = null
                                diagnosticsOpen = true
                            },
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
                            runtimeSession = runtimeSessions[selected.id],
                            operationBusy = operationBusy,
                            onStartRuntimeSession = { startRuntimeSession(selected) },
                            onStopRuntimeSession = { stopRuntimeSession(selected) },
                            onDiagnostics = {
                                diagnosticsGuestFilter = selected.id
                                diagnosticsOpen = true
                            },
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
                                if (!operationBusy) {
                                    operationBusy = true
                                    scope.launch {
                                        try {
                                            stopRuntimeSessionBeforeStorageChange(selected)
                                            withContext(Dispatchers.IO) {
                                                importer?.clearData(selected) ?: error("Registry is unavailable")
                                            }
                                            storageRefresh += 1
                                            recordDiagnostic(
                                                storageDiagnostic(
                                                    selected,
                                                    DiagnosticOperation.DATA_CLEAR,
                                                    "GUEST_DATA_CLEARED",
                                                    "Guest-owned data cleared; the imported APK and OBB files were retained.",
                                                    "Internal and app-specific external data directories were cleared.",
                                                ).toStoredDiagnostic(),
                                            )
                                            showOperationResult("Cleared guest-owned data. The imported APK and OBB files were retained.")
                                        } catch (cancelled: CancellationException) {
                                            throw cancelled
                                        } catch (failure: Exception) {
                                            val event = RuntimeDiagnosticClassifier.failure(
                                                DiagnosticOperation.DATA_CLEAR,
                                                failure.message ?: failure.javaClass.simpleName,
                                                guestId = selected.id,
                                                packageName = selected.packageName,
                                                exceptionType = failure.javaClass.name,
                                            )
                                            recordDiagnostic(event.toStoredDiagnostic())
                                            showOperationResult(event.summary)
                                        } finally {
                                            operationBusy = false
                                        }
                                    }
                                }
                            },
                            onRemove = {
                                if (!operationBusy) {
                                    operationBusy = true
                                    scope.launch {
                                        try {
                                            stopRuntimeSessionBeforeStorageChange(selected)
                                            withContext(Dispatchers.IO) {
                                                importer?.remove(selected) ?: error("Registry is unavailable")
                                            }
                                            apps.removeAll { it.id == selected.id }
                                            selectedId = null
                                            storage = null
                                            recordDiagnostic(
                                                storageDiagnostic(
                                                    selected,
                                                    DiagnosticOperation.APP_REMOVE,
                                                    "GUEST_APP_REMOVED",
                                                    "Imported guest removed from RetroBridge.",
                                                    "Only this guest's app-private files and registry entry were removed.",
                                                ).toStoredDiagnostic(),
                                            )
                                            showOperationResult("Removed ${selected.displayName} from RetroBridge.")
                                        } catch (cancelled: CancellationException) {
                                            throw cancelled
                                        } catch (failure: Exception) {
                                            val event = RuntimeDiagnosticClassifier.failure(
                                                DiagnosticOperation.APP_REMOVE,
                                                failure.message ?: failure.javaClass.simpleName,
                                                guestId = selected.id,
                                                packageName = selected.packageName,
                                                exceptionType = failure.javaClass.name,
                                            )
                                            recordDiagnostic(event.toStoredDiagnostic())
                                            showOperationResult(event.summary)
                                        } finally {
                                            operationBusy = false
                                        }
                                    }
                                }
                            },
                        )
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        runtimeClient.close()
        super.onDestroy()
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
    diagnosticCount: Int,
    canImport: Boolean,
    operationBusy: Boolean,
    onDiagnostics: () -> Unit,
    onImport: () -> Unit,
    onSelect: (GuestAppRecord) -> Unit,
) {
    var compatibilityExpanded by remember { mutableStateOf(false) }
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("RetroBridge", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("ARM32 compatibility runtime · experimental prototype", style = MaterialTheme.typography.bodyMedium)
        WarningCard(
            title = "Selected ARM32 native execution only",
            body = "Not all armeabi-v7a games are compatible. RetroBridge executes only selected ARM32 native libraries and entrypoints; it does not run APK Java/DEX, launch Android Activities, or virtualize the full framework. ABI detection and APK preflight are not launch guarantees; unsupported instructions, dependencies, syscalls, and APIs fail with diagnostics.",
        )
        if (registryProblem != null) {
            WarningCard("Registry could not be opened", registryProblem)
        }
        if (operationBusy) OperationProgress()
        OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text("Diagnostics ($diagnosticCount)")
        }
        Button(
            onClick = onImport,
            enabled = canImport && !operationBusy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Import APK")
        }
        Text("Imported applications (${apps.size})", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        if (apps.isEmpty()) {
            Text("No APKs imported. Choose a single APK to copy it into RetroBridge's private app storage.")
        } else {
            apps.forEach { record ->
                Card(
                    modifier = Modifier.fillMaxWidth().clickable(
                        role = Role.Button,
                        onClickLabel = "Open ${record.displayName}",
                        onClick = { onSelect(record) },
                    ),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(record.displayName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(record.packageName, style = MaterialTheme.typography.bodySmall)
                        Text("Imported · native loadability not verified", style = MaterialTheme.typography.labelMedium)
                        Text("Lifecycle: ${record.state.name.lowercase()} · Bundled ABI folder(s): ${record.guestAbis.joinToString().ifBlank { "none detected" }}")
                    }
                }
            }
        }
        HorizontalDivider()
        Text("Current compatibility", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        TextButton(onClick = { compatibilityExpanded = !compatibilityExpanded }) {
            Text(if (compatibilityExpanded) "Hide capability inventory" else "Show capability inventory")
        }
        if (compatibilityExpanded) CompatibilityReport.capabilities.forEach { CapabilityRow(it) }
    }
}

@androidx.compose.runtime.Composable
private fun AppDetailsScreen(
    modifier: Modifier,
    record: GuestAppRecord,
    storage: StorageBreakdown?,
    runtimeSession: RuntimeSessionUi?,
    operationBusy: Boolean,
    onStartRuntimeSession: () -> Unit,
    onStopRuntimeSession: () -> Unit,
    onDiagnostics: () -> Unit,
    onBack: () -> Unit,
    onAttachData: () -> Unit,
    onAttachObb: () -> Unit,
    onExport: () -> Unit,
    onClearData: () -> Unit,
    onRemove: () -> Unit,
) {
    var pendingAction by remember(record.id) { mutableStateOf<PendingAction?>(null) }
    var compatibilityExpanded by remember(record.id) { mutableStateOf(false) }
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
        WarningCard(
            title = "Imported · native launch not verified",
            body = "APK metadata and ELF preflight are inspection results only. No Ready state is inferred without verified dependencies and a completed selected runtime path.",
        )
        InfoRow("Package", record.packageName)
        InfoRow("Version", "${record.versionName ?: "unknown"} (${record.versionCode})")
        InfoRow("SDK range", "min ${record.minSdk ?: "unknown"} · target ${record.targetSdk ?: "unknown"}")
        InfoRow("Bundled native ABI folders", record.guestAbis.joinToString().ifBlank { "None detected" })
        InfoRow("Native ELF preflight", "Structural metadata only; not proof of library loadability")
        Text("Bundled native libraries", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
        if (record.nativeLibraries.isEmpty()) {
            Text("None detected")
        } else {
            record.nativeLibraries.toSortedMap().forEach { (abi, names) ->
                InfoRow(
                    "ABI $abi",
                    names.take(20).joinToString().let { listed ->
                        if (names.size > 20) "$listed … (${names.size} total)" else listed
                    },
                )
            }
        }
        InfoRow("Lifecycle", record.state.name.lowercase())
        InfoRow(
            "Last runtime outcome",
            record.launchHistory.lastOrNull()?.let { latest ->
                "${latest.outcome.lowercase().replace('_', ' ')}${latest.diagnostic?.let { ": $it" }.orEmpty()}"
            } ?: "Not attempted",
        )
        InfoRow(
            "Guest runtime",
            runtimeSession?.state ?: "Not queried in this screen (session state is service-owned)",
        )
        runtimeSession?.sessionId?.let { InfoRow("Runtime session", it) }
        runtimeSession?.let { InfoRow("Guest code executed", if (it.guestCodeStarted) "Yes" else "No") }
        runtimeSession?.let { InfoRow("Guest instructions", it.guestInstructions.toString()) }
        runtimeSession?.let { InfoRow("Applied relocations", it.relocationCount.toString()) }
        runtimeSession?.takeIf { it.jniOnLoadVersion >= 0 }?.let {
            InfoRow("JNI_OnLoad", "version 0x${it.jniOnLoadVersion.toUInt().toString(16)} · ${it.registeredNativeCount} native registration(s)")
        }
        runtimeSession?.takeIf { it.loadedLibraries.isNotEmpty() }?.let {
            InfoRow("Loaded libraries", it.loadedLibraries.joinToString())
        }
        runtimeSession?.takeIf { it.entrypointResults.isNotEmpty() }?.let {
            InfoRow("Native entrypoints", it.entrypointResults.joinToString("; "))
        }
        runtimeSession?.diagnosticEvent?.let { InfoRow("Latest runtime outcome", it.summary) }
        OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) { Text("View diagnostics") }
        InfoRow("APK SHA-256", record.sha256)
        InfoRow("Private APK path", record.originalApkPath)
        InfoRow("Split APKs", record.splitApkPaths.joinToString().ifBlank { "None" })
        InfoRow("Android/data archive", record.dataArchiveState.name.lowercase())
        InfoRow("OBB", "${record.obbState.name.lowercase()} · ${record.obbFiles.joinToString().ifBlank { "no files" }}")
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onAttachData, enabled = !operationBusy, modifier = Modifier.fillMaxWidth()) {
                Text("Attach data ZIP")
            }
            OutlinedButton(onClick = onAttachObb, enabled = !operationBusy, modifier = Modifier.fillMaxWidth()) {
                Text("Attach OBB / ZIP")
            }
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
        TextButton(onClick = { compatibilityExpanded = !compatibilityExpanded }) {
            Text(if (compatibilityExpanded) "Hide compatibility details" else "Show compatibility details")
        }
        if (compatibilityExpanded) CompatibilityReport.capabilities.forEach { CapabilityRow(it) }

        HorizontalDivider()
        Text("Recent preflight findings", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        InfoRow("Crash dumps", record.crashDumpPaths.joinToString().ifBlank { "None recorded" })
        if (record.diagnostics.isEmpty()) {
            Text("No preflight findings recorded. Import status still does not indicate runtime readiness.")
        } else {
            record.diagnostics.takeLast(8).reversed().forEach { diagnostic ->
                Text("${diagnostic.severity.uppercase()} · ${diagnostic.message}")
                diagnostic.nextAction?.let { Text("Next: $it", style = MaterialTheme.typography.bodySmall) }
            }
        }

        HorizontalDivider()
        Text("Runtime session controls", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        if (operationBusy) OperationProgress()
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onStartRuntimeSession,
                enabled = !operationBusy && runtimeSession?.sessionId == null,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Launch Guest Runtime") }
            OutlinedButton(
                onClick = onStopRuntimeSession,
                enabled = !operationBusy && runtimeSession?.sessionId != null,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Stop Guest Runtime") }
        }
        OutlinedButton(onClick = onExport, enabled = !operationBusy, modifier = Modifier.fillMaxWidth()) {
            Text("Export data ZIP")
        }
        Text(
            "Launch runs only supported ARM32 native constructors, JNI_OnLoad, and selected exported entrypoints in the bounded interpreter. " +
                "It does not execute APK Java bytecode, start an Android Activity, or virtualize the full Android framework. " +
                "Unsupported instructions, imports, and APIs fail with diagnostics.",
            style = MaterialTheme.typography.bodySmall,
        )
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { pendingAction = PendingAction.CLEAR_DATA },
                enabled = !operationBusy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Clear Data") }
            OutlinedButton(
                onClick = { pendingAction = PendingAction.REMOVE },
                enabled = !operationBusy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Remove") }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@androidx.compose.runtime.Composable
private fun OperationProgress() {
    Row(
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
        Text("Operation in progress…")
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

private fun apkImportedDiagnostic(record: GuestAppRecord) = RuntimeDiagnostic(
    timestampEpochMs = record.createdAtEpochMs,
    severity = DiagnosticSeverity.INFO,
    category = DiagnosticCategory.APK_IMPORT,
    code = "APK_IMPORTED",
    component = "APK importer",
    operation = DiagnosticOperation.APK_IMPORT,
    summary = "APK imported; native launchability is not verified.",
    detail = "Detected ABI folders: ${record.guestAbis.joinToString().ifBlank { "none" }}; this is not dependency, relocation, Java/DEX, or Activity validation.",
    guestId = record.id,
    packageName = record.packageName,
    nextAction = "Review preflight findings, then attempt only the bounded ARM32 native path if an ARM32 library is present.",
)

private fun storageDiagnostic(
    record: GuestAppRecord,
    operation: DiagnosticOperation,
    code: String,
    summary: String,
    detail: String,
) = RuntimeDiagnostic(
    timestampEpochMs = System.currentTimeMillis(),
    severity = DiagnosticSeverity.INFO,
    category = DiagnosticCategory.FILESYSTEM,
    code = code,
    component = if (operation == DiagnosticOperation.APP_REMOVE) "Guest manager" else "Guest storage",
    operation = operation,
    summary = summary,
    detail = detail,
    guestId = record.id,
    packageName = record.packageName,
    nextAction = when (operation) {
        DiagnosticOperation.DATA_EXPORT -> "Review the exported archive; its destination and contents may be visible outside RetroBridge's private storage."
        DiagnosticOperation.DATA_CLEAR -> "The imported APK and OBB files remain available; guest data must be reattached or recreated as needed."
        DiagnosticOperation.APP_REMOVE -> "Import the APK again to create a new isolated guest record."
        else -> "Content is mapped only to RetroBridge's app-private guest storage; successful attachment does not prove that the game can use it."
    },
)

private data class RuntimeSessionUi(
    val sessionId: String?,
    val state: String,
    val guestCodeStarted: Boolean,
    val guestInstructions: Long,
    val relocationCount: Int,
    val jniOnLoadVersion: Int,
    val registeredNativeCount: Int,
    val loadedLibraries: List<String>,
    val entrypointResults: List<String>,
    val diagnostic: String,
    val diagnosticEvent: RuntimeDiagnostic?,
) {
    companion object {
        fun from(reply: GuestRuntimeSessionReply) = RuntimeSessionUi(
            sessionId = reply.sessionId,
            state = reply.state,
            guestCodeStarted = reply.guestCodeStarted,
            guestInstructions = reply.guestInstructions,
            relocationCount = reply.relocationCount,
            jniOnLoadVersion = reply.jniOnLoadVersion,
            registeredNativeCount = reply.registeredNativeCount,
            loadedLibraries = reply.loadedLibraries,
            entrypointResults = reply.entrypointResults,
            diagnostic = reply.diagnostic,
            diagnosticEvent = reply.diagnosticEvent,
        )
    }
}

private enum class PendingAction { CLEAR_DATA, REMOVE }
