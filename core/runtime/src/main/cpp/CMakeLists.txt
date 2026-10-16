cmake_minimum_required(VERSION 3.22.1)
project(retrobridge_runtime LANGUAGES CXX)

set(RETROBRIDGE_RUNTIME_SOURCES
    src/elf32_image.cpp
    src/arm32_interpreter.cpp
    src/guest_memory.cpp
    src/elf32_loader.cpp
    src/guest_lifecycle.cpp
    src/handle_table.cpp
    src/translation_engine.cpp
)

if(ANDROID)
    add_library(retrobridge_runtime SHARED ${RETROBRIDGE_RUNTIME_SOURCES})
else()
    add_library(retrobridge_runtime STATIC ${RETROBRIDGE_RUNTIME_SOURCES})
endif()

target_include_directories(retrobridge_runtime
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(retrobridge_runtime PUBLIC cxx_std_20)
target_compile_options(retrobridge_runtime PRIVATE -Wall -Wextra -Wpedantic)
