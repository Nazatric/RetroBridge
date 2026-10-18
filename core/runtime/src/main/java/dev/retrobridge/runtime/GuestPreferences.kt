package dev.retrobridge.runtime

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Small typed, app-private preferences store for [GuestContextWrapper]. This is deliberately not
 * android.content.SharedPreferences: there are no listeners, cross-process locks, or XML format.
 */
class GuestPreferences internal constructor(private val file: Path) {
    private var values: MutableMap<String, Any> = load()

    @Synchronized
    fun getString(key: String, defaultValue: String? = null): String? {
        validateKey(key)
        val value = values[key] ?: return defaultValue
        return value as? String ?: throw ClassCastException("Preference '$key' has a different stored type")
    }

    @Synchronized
    fun getBoolean(key: String, defaultValue: Boolean = false): Boolean = typedValue(key, defaultValue)

    @Synchronized
    fun getInt(key: String, defaultValue: Int = 0): Int = typedValue(key, defaultValue)

    @Synchronized
    fun getLong(key: String, defaultValue: Long = 0L): Long = typedValue(key, defaultValue)

    @Synchronized
    fun getFloat(key: String, defaultValue: Float = 0f): Float = typedValue(key, defaultValue)

    @Synchronized
    fun getStringSet(key: String, defaultValue: Set<String> = emptySet()): Set<String> {
        validateKey(key)
        val value = values[key] ?: return defaultValue.toSet()
        if (value !is Set<*> || value.any { it !is String }) {
            throw ClassCastException("Preference '$key' has a different stored type")
        }
        return value.filterIsInstance<String>().toSet()
    }

    @Synchronized
    fun contains(key: String): Boolean {
        validateKey(key)
        return values.containsKey(key)
    }

    @Synchronized
    fun putString(key: String, value: String?): Boolean = update(key, value)

    @Synchronized
    fun putBoolean(key: String, value: Boolean): Boolean = update(key, value)

    @Synchronized
    fun putInt(key: String, value: Int): Boolean = update(key, value)

    @Synchronized
    fun putLong(key: String, value: Long): Boolean = update(key, value)

    @Synchronized
    fun putFloat(key: String, value: Float): Boolean = update(key, value)

    @Synchronized
    fun putStringSet(key: String, value: Set<String>?): Boolean =
        update(key, value?.toSet())

    @Synchronized
    fun remove(key: String): Boolean {
        validateKey(key)
        if (!values.containsKey(key)) return true
        val updated = values.toMutableMap().apply { remove(key) }
        return persistAndPublish(updated)
    }

    @Synchronized
    fun clear(): Boolean = persistAndPublish(mutableMapOf())

    private inline fun <reified T : Any> typedValue(key: String, defaultValue: T): T {
        validateKey(key)
        val value = values[key] ?: return defaultValue
        if (value !is T) throw ClassCastException("Preference '$key' has a different stored type")
        return value
    }

    private fun update(key: String, value: Any?): Boolean {
        validateKey(key)
        if (value is String) validateText(value, MAX_STRING_BYTES, "preference string")
        if (value is Set<*>) {
            require(value.size <= MAX_SET_ENTRIES && value.all { it is String }) { "Invalid guest preference string set" }
            value.filterIsInstance<String>().forEach { validateText(it, MAX_STRING_BYTES, "preference set item") }
        }
        val updated = values.toMutableMap()
        if (value == null) updated.remove(key) else updated[key] = value
        if (updated.size > MAX_ENTRIES) throw IllegalArgumentException("Guest preferences exceed the key limit")
        return persistAndPublish(updated)
    }

    private fun persistAndPublish(updated: MutableMap<String, Any>): Boolean {
        return try {
            writeAtomically(updated)
            values = updated
            true
        } catch (_: IOException) {
            false
        }
    }

    private fun load(): MutableMap<String, Any> {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return mutableMapOf()
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw SecurityException("Guest preferences are not a regular app-private file")
        }
        if (Files.size(file) > MAX_FILE_BYTES) throw IOException("Guest preferences exceed the file-size limit")
        return Files.newInputStream(file).use { stream ->
            DataInputStream(stream).use { input ->
                if (input.readInt() != MAGIC || input.readInt() != FORMAT_VERSION) {
                    throw IOException("Guest preferences have an unsupported file format")
                }
                val count = input.readInt()
                if (count !in 0..MAX_ENTRIES) throw IOException("Guest preferences contain an invalid key count")
                val loaded = LinkedHashMap<String, Any>(count)
                repeat(count) {
                    val key = input.readBoundedString(MAX_KEY_BYTES)
                    validateKey(key)
                    val type = input.readUnsignedByte()
                    val value: Any = when (type) {
                        TYPE_STRING -> input.readBoundedString(MAX_STRING_BYTES).also {
                            validateText(it, MAX_STRING_BYTES, "preference string")
                        }
                        TYPE_BOOLEAN -> when (val encoded = input.readUnsignedByte()) {
                            0 -> false
                            1 -> true
                            else -> throw IOException("Invalid boolean preference encoding: $encoded")
                        }
                        TYPE_INT -> input.readInt()
                        TYPE_LONG -> input.readLong()
                        TYPE_FLOAT -> Float.fromBits(input.readInt())
                        TYPE_STRING_SET -> {
                            val setCount = input.readInt()
                            if (setCount !in 0..MAX_SET_ENTRIES) throw IOException("Guest preference set exceeds its entry limit")
                            buildSet(setCount) {
                                repeat(setCount) {
                                    val item = input.readBoundedString(MAX_STRING_BYTES)
                                    validateText(item, MAX_STRING_BYTES, "preference set item")
                                    if (!add(item)) throw IOException("Guest preference set contains a duplicate value")
                                }
                            }
                        }
                        else -> throw IOException("Unknown guest preference value type")
                    }
                    if (loaded.put(key, value) != null) throw IOException("Guest preferences contain a duplicate key")
                }
                if (input.read() != -1) throw IOException("Guest preferences contain trailing bytes")
                loaded
            }
        }
    }

    private fun writeAtomically(updated: Map<String, Any>) {
        val parent = file.parent ?: throw IOException("Guest preferences have no parent directory")
        if (Files.isSymbolicLink(file)) throw SecurityException("Guest preferences cannot be a symbolic link")
        val bytes = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output ->
                output.writeInt(MAGIC)
                output.writeInt(FORMAT_VERSION)
                output.writeInt(updated.size)
                for ((key, value) in updated.toSortedMap()) {
                    output.writeBoundedString(key, MAX_KEY_BYTES)
                    when (value) {
                        is String -> {
                            output.writeByte(TYPE_STRING)
                            output.writeBoundedString(value, MAX_STRING_BYTES)
                        }
                        is Boolean -> {
                            output.writeByte(TYPE_BOOLEAN)
                            output.writeByte(if (value) 1 else 0)
                        }
                        is Int -> {
                            output.writeByte(TYPE_INT)
                            output.writeInt(value)
                        }
                        is Long -> {
                            output.writeByte(TYPE_LONG)
                            output.writeLong(value)
                        }
                        is Float -> {
                            output.writeByte(TYPE_FLOAT)
                            output.writeInt(value.toBits())
                        }
                        is Set<*> -> {
                            val items = value.filterIsInstance<String>().sorted()
                            if (items.size != value.size || items.size > MAX_SET_ENTRIES) {
                                throw IOException("Guest preference set is invalid")
                            }
                            output.writeByte(TYPE_STRING_SET)
                            output.writeInt(items.size)
                            items.forEach { output.writeBoundedString(it, MAX_STRING_BYTES) }
                        }
                        else -> throw IOException("Unsupported guest preference value type")
                    }
                }
                output.flush()
                buffer.toByteArray()
            }
        }
        if (bytes.size > MAX_FILE_BYTES) throw IOException("Guest preferences exceed the file-size limit")

        val temporary = Files.createTempFile(parent, ".guest-preferences-", ".tmp")
        try {
            Files.write(temporary, bytes, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)
            if (Files.isSymbolicLink(file)) throw SecurityException("Guest preferences cannot be a symbolic link")
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun validateKey(key: String) {
        validateText(key, MAX_KEY_BYTES, "preference key")
        require(key.isNotEmpty()) { "Guest preference key cannot be empty" }
    }

    private fun validateText(value: String, maximumBytes: Int, label: String) {
        require(value.length <= maximumBytes && '\u0000' !in value) { "Invalid $label" }
        require(value.toByteArray(Charsets.UTF_8).size <= maximumBytes) { "Invalid $label" }
    }

    private fun DataInputStream.readBoundedString(maximumBytes: Int): String {
        val length = readInt()
        if (length !in 0..maximumBytes) throw IOException("Guest preference string exceeds its size limit")
        val bytes = ByteArray(length)
        readFully(bytes)
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (failure: java.nio.charset.CharacterCodingException) {
            throw IOException("Guest preference string is not valid UTF-8", failure)
        }
    }

    private fun DataOutputStream.writeBoundedString(value: String, maximumBytes: Int) {
        if (value.length > maximumBytes) throw IOException("Guest preference string exceeds its size limit")
        val bytes = value.toByteArray(Charsets.UTF_8)
        if (bytes.size > maximumBytes) throw IOException("Guest preference string exceeds its size limit")
        writeInt(bytes.size)
        write(bytes)
    }

    private companion object {
        const val MAGIC = 0x47505246 // "GPRF"
        const val FORMAT_VERSION = 1
        const val TYPE_STRING = 1
        const val TYPE_BOOLEAN = 2
        const val TYPE_INT = 3
        const val TYPE_LONG = 4
        const val TYPE_FLOAT = 5
        const val TYPE_STRING_SET = 6
        const val MAX_ENTRIES = 4096
        const val MAX_SET_ENTRIES = 1024
        const val MAX_KEY_BYTES = 256
        const val MAX_STRING_BYTES = 64 * 1024
        const val MAX_FILE_BYTES = 1024 * 1024
    }
}
