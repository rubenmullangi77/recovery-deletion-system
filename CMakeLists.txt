cmake_minimum_required(VERSION 3.20)
project(ForensiVault VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Export compile_commands.json for Clang LSP server (clangd)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(CMAKE_EXPORT_COMPILE_COMMANDS)
    file(CREATE_LINK
        "${CMAKE_BINARY_DIR}/compile_commands.json"
        "${CMAKE_SOURCE_DIR}/compile_commands.json"
        SYMBOLIC
        COPY_ON_ERROR
    )
endif()

find_package(Threads REQUIRED)

# Compiler flags and warnings
if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Global output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Backend subdirectory
add_subdirectory(backend)

# Unit tests (Disabled by default)
option(BUILD_TESTING "Build automated unit test suite" OFF)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

