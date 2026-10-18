package dev.retrobridge.runtime

/** Injectable seam for service orchestration tests; production uses the JNI-backed controller. */
interface NativeRuntimeController {
    fun createSession(context: GuestRuntimeContext): Long
    fun inspectLibrary(sessionId: Long, libraryPath: String): NativeLibraryMetadata
    fun loadLibrary(sessionId: Long, libraryPath: String, expectedSha256: String): NativeLoadResult
    fun execute(sessionId: Long, instructionBudget: Long): NativeExecutionReport
    fun destroySession(sessionId: Long)
}

object JniNativeRuntimeController : NativeRuntimeController {
    override fun createSession(context: GuestRuntimeContext): Long {
        val guestContext = GuestContextWrapper(context).apply { prepareStorageDirectories() }
        return RetroBridgeNativeBridge.nativeCreateSession(
            guestContext.packageName,
            guestContext.dataDir.toString(),
            guestContext.externalDataDir.toString(),
            guestContext.obbDir.toString(),
            context.appRoot.resolve("runtime/native").toString(),
        )
    }

    override fun inspectLibrary(sessionId: Long, libraryPath: String): NativeLibraryMetadata =
        RetroBridgeNativeBridge.nativeInspectLibrary(sessionId, libraryPath)

    override fun loadLibrary(
        sessionId: Long,
        libraryPath: String,
        expectedSha256: String,
    ): NativeLoadResult = RetroBridgeNativeBridge.nativeLoadLibrary(sessionId, libraryPath, expectedSha256)

    override fun execute(sessionId: Long, instructionBudget: Long): NativeExecutionReport =
        RetroBridgeNativeBridge.nativeExecute(sessionId, instructionBudget)

    override fun destroySession(sessionId: Long) = RetroBridgeNativeBridge.nativeDestroySession(sessionId)
}
