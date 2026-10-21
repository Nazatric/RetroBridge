# Runtime diagnostics

RetroBridge distinguishes **Imported**, preflighted, and actual selected native-runtime outcomes. Import and header checks do not establish compatibility; a successful run establishes only that one selected native path completed under the current interpreter, linker, and resource limits.

## Event model and persistence

`core/services/.../RuntimeDiagnostic.kt` defines the structured event dimensions shared by runtime orchestration and the app: severity, stable category/code, component, operation stage, app/guest identity, concise summary, technical detail, library, file, symbol, guest address, instruction word/halfword, and a suggested next action. Current runtime messages are classified at the Kotlin runtime boundary; the classifier does not change the underlying failure or turn unsupported behavior into success. The ARM interpreter now includes the guest PC and exact encoding on instruction faults where it can.

The Messenger service transports structured fields as primitive `Bundle` values. The app persists runtime/import/storage outcomes in its private `RetroBridge/diagnostics.json` history using bounded, atomic JSON replacement. The history retains at most 500 event groups and is limited to 32 MiB on both read and write; an oversized or malformed history is reported without overwriting the original. Events with identical code/category/component/app/summary and the same library, file, symbol, guest address, and instruction encoding coalesce within 60 seconds into one row with an incremented occurrence count and last-occurrence timestamp; failures at different guest locations remain separate. Per-APK structural preflight findings (at most 65 per APK) stay in the app registry and are included in the viewer. File paths are capped at 1,024 characters through model validation and IPC. App launch history is separately capped at 200 outcomes per imported record.

The Diagnostics view searches summary/detail/code/component/operation/app/library/file/symbol/address/instruction, filters by severity/category/component/app, expands technical details, copies an event, and exports the currently filtered snapshot as JSON. The export can contain package names, guest paths, library names, symbols, and execution addresses; review it before sharing.

## Categories

Stable category identifiers include `APK_IMPORT`, `UNSUPPORTED_ABI`, `ELF_LOADING`, `MISSING_LIBRARY`, `UNRESOLVED_SYMBOL`, `UNSUPPORTED_INSTRUCTION`, `ABI_CONVERSION`, `NATIVE_RUNTIME`, `JNI`, `ANDROID_FRAMEWORK`, `FILESYSTEM`, `GRAPHICS_AUDIO`, `RESOURCE_EXHAUSTION`, `GUEST_CRASH`, `INTERNAL_DEFECT`, and `GENERAL`. Operation stages distinguish APK import/preflight, data/OBB import, export, and clear, guest removal, guest-context validation, native extraction/session initialization, ELF inspection, dependency resolution, library mapping, native execution, JNI initialization, session management/stop, IPC, and diagnostic export.

Examples of stable runtime failure codes include `ARM32_LIBRARY_NOT_FOUND`, `MISSING_NATIVE_LIBRARY`, `UNRESOLVED_NATIVE_SYMBOL`, `UNSUPPORTED_ARM_INSTRUCTION`, `ELF_LOAD_OR_RELOCATION_FAILED`, `GUEST_DATA_CLEAR_FAILED`, `GUEST_APP_REMOVE_FAILED`, `RUNTIME_RESOURCE_LIMIT`, and `RUNTIME_SESSION_STOPPED`. Codes are identifiers, not a promise that every raw native diagnostic has a unique C++-level code; remaining unclassified messages retain their raw bounded detail and a generic runtime code.

## Important limits

- Process death, native abort, power loss, or storage failure can prevent a final event from being persisted. Such cases are not represented as recovered crashes.
- The current native C++ report is still a bounded string diagnostic list. The Kotlin classifier adds stable fields at the runtime boundary; it is not yet a typed C++ diagnostic ABI for every native error path.
- Guest file/address/instruction fields are populated only when the underlying message contains them. Missing fields mean “not reported,” not “not applicable.”
- No imported app is marked Ready based on APK import, ABI cataloging, or ELF preflight. Java/DEX execution, guest Activities, full Android framework behavior, complete ARMv7, exception unwinding, and general game compatibility remain unsupported or partial as documented in the [compatibility matrix](compatibility-matrix.md).
