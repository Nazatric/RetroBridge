package dev.retrobridge.runtime

/** JNI-facing ARM32 ELF metadata. This validates structure only; it does not execute the image. */
data class NativeLibraryMetadata(
    val valid: Boolean,
    val libraryName: String,
    val soname: String,
    val neededLibraries: Array<String>,
    val diagnostic: String,
)

/** Result of mapping one verified, app-private ARM32 shared object into guest memory. */
data class NativeLoadResult(
    val loaded: Boolean,
    val libraryName: String,
    val loadAddress: Long,
    val neededLibraries: Array<String>,
    val diagnostic: String,
)

/** Details produced by interpreter-backed constructors, JNI_OnLoad, and supported entrypoints. */
data class NativeExecutionReport(
    val success: Boolean,
    val guestInstructions: Long,
    val relocationCount: Int,
    val jniOnLoadVersion: Int,
    val registeredNativeCount: Int,
    val loadedLibraries: Array<String>,
    val entrypointResults: Array<String>,
    val diagnostics: Array<String>,
)

/** Host JNI ownership boundary for an isolated, bounded ARM32 interpreter session. */
object RetroBridgeNativeBridge {
    init {
        System.loadLibrary("retrobridge_runtime")
    }

    external fun nativeCreateSession(
        packageName: String,
        internalDirectory: String,
        externalDataDirectory: String,
        obbDirectory: String,
        nativeLibraryRoot: String,
    ): Long

    external fun nativeInspectLibrary(sessionId: Long, libraryPath: String): NativeLibraryMetadata

    external fun nativeLoadLibrary(
        sessionId: Long,
        libraryPath: String,
        expectedSha256: String,
    ): NativeLoadResult

    external fun nativeExecute(sessionId: Long, instructionBudget: Long): NativeExecutionReport

    /** Runs bounded guest destructors, then releases the interpreter, VFS, heap and thunk state. */
    external fun nativeDestroySession(sessionId: Long)
}
