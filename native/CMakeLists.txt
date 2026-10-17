cmake_minimum_required(VERSION 3.22.1)
project(retrobridge_native_verification LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
enable_testing()

add_subdirectory(../core/runtime/src/main/cpp runtime)

add_executable(retrobridge_native_tests tests/native_tests.cpp)
target_link_libraries(retrobridge_native_tests PRIVATE retrobridge_runtime)
target_compile_options(retrobridge_native_tests PRIVATE -Wall -Wextra -Wpedantic)

add_executable(retrobridge_elf_inspect tools/elf32_inspect.cpp)
target_link_libraries(retrobridge_elf_inspect PRIVATE retrobridge_runtime)
target_compile_options(retrobridge_elf_inspect PRIVATE -Wall -Wextra -Wpedantic)

add_executable(retrobridge_arm32_fixture_runner tools/arm32_fixture_runner.cpp)
target_link_libraries(retrobridge_arm32_fixture_runner PRIVATE retrobridge_runtime)
target_compile_options(retrobridge_arm32_fixture_runner PRIVATE -Wall -Wextra -Wpedantic)

add_executable(retrobridge_arm32_benchmark tools/arm32_interpreter_benchmark.cpp)
target_link_libraries(retrobridge_arm32_benchmark PRIVATE retrobridge_runtime)
target_compile_options(retrobridge_arm32_benchmark PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME native_core COMMAND retrobridge_native_tests)

if(RETROBRIDGE_ARM32_VFP_EXECUTABLE)
    if(NOT EXISTS "${RETROBRIDGE_ARM32_VFP_EXECUTABLE}")
        message(FATAL_ERROR "RETROBRIDGE_ARM32_VFP_EXECUTABLE does not exist: ${RETROBRIDGE_ARM32_VFP_EXECUTABLE}")
    endif()
    add_test(
        NAME arm32_vfp_executable_execution
        COMMAND retrobridge_arm32_fixture_runner "${RETROBRIDGE_ARM32_VFP_EXECUTABLE}"
    )
endif()

if(RETROBRIDGE_ARM32_EXECUTABLE)
    if(NOT EXISTS "${RETROBRIDGE_ARM32_EXECUTABLE}")
        message(FATAL_ERROR "RETROBRIDGE_ARM32_EXECUTABLE does not exist: ${RETROBRIDGE_ARM32_EXECUTABLE}")
    endif()
    add_test(
        NAME arm32_guest_executable_inspection
        COMMAND retrobridge_elf_inspect "${RETROBRIDGE_ARM32_EXECUTABLE}" "org.retrobridge.ci.guest"
    )
    add_test(
        NAME arm32_guest_executable_execution
        COMMAND retrobridge_arm32_fixture_runner "${RETROBRIDGE_ARM32_EXECUTABLE}"
    )
endif()

if(RETROBRIDGE_ARM32_SHARED_LIBRARY)
    if(NOT EXISTS "${RETROBRIDGE_ARM32_SHARED_LIBRARY}")
        message(FATAL_ERROR "RETROBRIDGE_ARM32_SHARED_LIBRARY does not exist: ${RETROBRIDGE_ARM32_SHARED_LIBRARY}")
    endif()
    add_test(
        NAME arm32_shared_library_inspection
        COMMAND retrobridge_elf_inspect "${RETROBRIDGE_ARM32_SHARED_LIBRARY}" "org.retrobridge.ci.guest"
    )
    set_tests_properties(arm32_shared_library_inspection PROPERTIES PASS_REGULAR_EXPRESSION "needs: libc[.]so")
endif()
