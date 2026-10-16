package dev.retrobridge.manager

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

interface GuestAppRepository {
    fun list(): List<GuestAppRecord>
    fun get(id: String): GuestAppRecord?
    fun upsert(record: GuestAppRecord)
    fun update(id: String, transform: (GuestAppRecord) -> GuestAppRecord): GuestAppRecord
    fun remove(id: String): GuestAppRecord?
}

/** Small, app-private JSON registry with validated records and atomic replacement. */
class FileGuestAppRepository(
    private val registryFile: Path,
) : GuestAppRepository {
    private val lock = ReentrantReadWriteLock()
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
    }
    private val serializer = ListSerializer(GuestAppRecord.serializer())
    private var records: LinkedHashMap<String, GuestAppRecord> = load()

    override fun list(): List<GuestAppRecord> = lock.read {
        records.values.sortedByDescending(GuestAppRecord::createdAtEpochMs)
    }

    override fun get(id: String): GuestAppRecord? = lock.read { records[id] }

    override fun upsert(record: GuestAppRecord) = lock.write {
        record.validate()
        val next = LinkedHashMap(records)
        next[record.id] = record
        persist(next)
        records = next
    }

    override fun update(
        id: String,
        transform: (GuestAppRecord) -> GuestAppRecord,
    ): GuestAppRecord = lock.write {
        val current = records[id] ?: throw NoSuchElementException("Unknown guest application ID: $id")
        val updated = transform(current)
        require(updated.id == current.id) { "An update cannot change the application ID" }
        updated.validate()
        val next = LinkedHashMap(records)
        next[id] = updated
        persist(next)
        records = next
        updated
    }

    override fun remove(id: String): GuestAppRecord? = lock.write {
        val current = records[id] ?: return@write null
        val next = LinkedHashMap(records)
        next.remove(id)
        persist(next)
        records = next
        current
    }

    private fun load(): LinkedHashMap<String, GuestAppRecord> {
        if (!Files.exists(registryFile)) return linkedMapOf()
        try {
            val contents = Files.newBufferedReader(registryFile, StandardCharsets.UTF_8).use { it.readText() }
            val decoded = json.decodeFromString(serializer, contents)
            val result = linkedMapOf<String, GuestAppRecord>()
            decoded.forEach { record ->
                record.validate()
                check(result.put(record.id, record) == null) { "Duplicate guest ID in registry: ${record.id}" }
            }
            return result
        } catch (failure: Exception) {
            throw IllegalStateException(
                "Cannot read RetroBridge registry at $registryFile; the original file was left untouched",
                failure,
            )
        }
    }

    private fun persist(next: LinkedHashMap<String, GuestAppRecord>) {
        val parent = registryFile.toAbsolutePath().normalize().parent
            ?: throw IllegalArgumentException("Registry path must have a parent directory")
        Files.createDirectories(parent)
        val normalizedRegistry = registryFile.toAbsolutePath().normalize()
        val temporary = Files.createTempFile(parent, "${registryFile.fileName}.", ".tmp")
        try {
            Files.newBufferedWriter(
                temporary,
                StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            ).use { writer ->
                writer.write(json.encodeToString(serializer, next.values.toList()))
            }
            try {
                Files.move(
                    temporary,
                    normalizedRegistry,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary, normalizedRegistry, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }
}
