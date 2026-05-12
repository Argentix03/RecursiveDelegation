cmake_minimum_required(VERSION 3.14)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

project(RecursiveDelegationTests CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W3 /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

include(FetchContent)

# Pin to a known-good gtest release. Source archive download, no git submodule required.
FetchContent_Declare(
    googletest
    URL      https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    URL_HASH SHA256=1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4
)

# Force shared CRT (matches the EXE project's default Debug/Release x64 settings).
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

set(CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../RecursiveDelegation")

add_library(rd_core STATIC
    "${CORE_DIR}/RecursiveDelegationCore.cpp"
    "${CORE_DIR}/RecursiveDelegationEngine.cpp"
    "${CORE_DIR}/CaptureStub.asm"
)
target_include_directories(rd_core PUBLIC "${CORE_DIR}")

# The test binary acts as its own child process in delegation E2E tests, so it
# links the engine and provides its own main() that dispatches child mode before
# initializing GoogleTest. We deliberately do NOT link GTest::gtest_main.
add_executable(rd_core_tests
    test_core.cpp
)
target_link_libraries(rd_core_tests PRIVATE rd_core GTest::gtest)

include(GoogleTest)
gtest_discover_tests(rd_core_tests)
