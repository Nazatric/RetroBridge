package dev.retrobridge.manager

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

object GuestDiagnosticJson {
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
    }
    private val serializer = ListSerializer(GuestDiagnostic.serializer())

    fun encode(events: List<GuestDiagnostic>): String = json.encodeToString(serializer, events)

    fun decode(contents: String): List<GuestDiagnostic> = json.decodeFromString(serializer, contents)
}

/** App-private diagnostic history with bounded retention and repeat-event coalescing. */
class FileGuestDiagnosticRepository(
    private val historyFile: Path,
    private val maximumEvents: Int = 500,
    private val coalesceWindowMs: Long = 60_000L,
) {
    private val lock = ReentrantReadWriteLock()
    private var events = load()

    init {
        require(maximumEvents in 1..10_000) { "Diagnostic history bound is invalid" }
        require(coalesceWindowMs >= 0L) { "Diagnostic coalescing window cannot be negative" }
    }

    fun list(): List<GuestDiagnostic> = lock.read { events.toList() }

    fun append(event: GuestDiagnostic): List<GuestDiagnostic> = appendAll(listOf(event))

    fun appendAll(incoming: List<GuestDiagnostic>): List<GuestDiagnostic> = lock.write {
        if (incoming.isEmpty()) return@write events.toList()
        val next = events.toMutableList()
        incoming.forEach { event ->
            event.validate()
            val matchIndex = next.indexOfLast { old ->
                sameEvent(old, event) &&
                    event.timestampEpochMs >= (old.lastOccurredAtEpochMs ?: old.timestampEpochMs) &&
                    event.timestampEpochMs - (old.lastOccurredAtEpochMs ?: old.timestampEpochMs) <= coalesceWindowMs
            }
            if (matchIndex >= 0) {
                val old = next[matchIndex]
                next[matchIndex] = old.copy(
                    occurrences = (old.occurrences.toLong() + event.occurrences).coerceAtMost(MAX_OCCURRENCES.toLong()).toInt(),
                    lastOccurredAtEpochMs = event.lastOccurredAtEpochMs ?: event.timestampEpochMs,
                    detail = event.detail ?: old.detail,
                    nextAction = event.nextAction ?: old.nextAction,
                )
            } else {
                next += event
            }
        }
        val bounded = next.takeLast(maximumEvents)
        persist(bounded)
        events = bounded
        events.toList()
    }

    fun exportJson(snapshot: List<GuestDiagnostic> = list()): String = GuestDiagnosticJson.encode(snapshot)

    private fun sameEvent(left: GuestDiagnostic, right: GuestDiagnostic) =
        left.guestId == right.guestId &&
            left.packageName == right.packageName &&
            left.code == right.code &&
            left.category == right.category &&
            left.operation == right.operation &&
            left.component == right.component &&
            left.message == right.message &&
            left.library == right.library &&
            left.file == right.file &&
            left.symbol == right.symbol &&
            left.guestAddress == right.guestAddress &&
            left.instruction == right.instruction

    private fun load(): List<GuestDiagnostic> {
        if (!Files.exists(historyFile, LinkOption.NOFOLLOW_LINKS)) return emptyList()
        try {
            rejectSymlinks(historyFile.toAbsolutePath().normalize())
            if (Files.size(historyFile) > MAX_HISTORY_FILE_BYTES) {
                throw IllegalStateException("Diagnostic history exceeds its $MAX_HISTORY_FILE_BYTES-byte read bound")
            }
            val contents = Files.newInputStream(historyFile, LinkOption.NOFOLLOW_LINKS)
                .bufferedReader(StandardCharsets.UTF_8)
                .use { it.readText() }
            return GuestDiagnosticJson.decode(contents).onEach(GuestDiagnostic::validate).takeLast(maximumEvents)
        } catch (failure: Exception) {
            throw IllegalStateException(
                "Cannot read RetroBridge diagnostic history at $historyFile; the original file was left untouched",
                failure,
            )
        }
    }

    private fun persist(next: List<GuestDiagnostic>) {
        val normalized = historyFile.toAbsolutePath().normalize()
        val parent = normalized.parent ?: throw IllegalArgumentException("Diagnostic history path must have a parent")
        rejectSymlinks(parent)
        Files.createDirectories(parent)
        rejectSymlinks(parent)
        rejectSymlinks(normalized)
        val encoded = GuestDiagnosticJson.encode(next).toByteArray(StandardCharsets.UTF_8)
        require(encoded.size.toLong() <= MAX_HISTORY_FILE_BYTES) {
            "Diagnostic history exceeds its $MAX_HISTORY_FILE_BYTES-byte write bound"
        }
        val temporary = Files.createTempFile(parent, "${historyFile.fileName}.", ".tmp")
        try {
            Files.newOutputStream(
                temporary,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            ).use { output -> output.write(encoded) }
            try {
                Files.move(temporary, normalized, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary, normalized, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun rejectSymlinks(path: Path) {
        var current = path.root ?: throw SecurityException("Diagnostic history path must be absolute")
        for (segment in path) {
            current = current.resolve(segment)
            if (Files.isSymbolicLink(current)) throw SecurityException("Symbolic links are not allowed in diagnostic history paths")
        }
    }

    companion object {
        private const val MAX_OCCURRENCES = 1_000_000
        private const val MAX_HISTORY_FILE_BYTES = 32L * 1024 * 1024
    }
}
