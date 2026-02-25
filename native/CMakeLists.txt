cmake_minimum_required(VERSION 3.16)
project(aegisd VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(AEGIS_ENABLE_BPF "Enable eBPF/LSM support (requires libbpf, clang, bpftool)" OFF)
option(AEGIS_ENABLE_TESTS "Build tests" ON)

# --- Dependencies ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAML_CPP REQUIRED yaml-cpp)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(LIBCURL REQUIRED libcurl)

# --- eBPF (optional, Fase 2+) ---
if(AEGIS_ENABLE_BPF)
    pkg_check_modules(LIBBPF REQUIRED libbpf>=1.0)
    pkg_check_modules(LIBELF REQUIRED libelf)
    pkg_check_modules(ZLIB REQUIRED zlib)

    find_program(CLANG clang REQUIRED)
    find_program(BPFTOOL bpftool REQUIRED)

    # Detect architecture for vmlinux
    execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(ARCH STREQUAL "x86_64")
        set(VMLINUX_H "${CMAKE_SOURCE_DIR}/vmlinux/vmlinux_x86_64.h")
    elseif(ARCH MATCHES "aarch64|arm64")
        set(VMLINUX_H "${CMAKE_SOURCE_DIR}/vmlinux/vmlinux_aarch64.h")
    else()
        message(FATAL_ERROR "Unsupported architecture: ${ARCH}")
    endif()

    # Compile BPF program
    set(BPF_SRC "${CMAKE_SOURCE_DIR}/src/bpf/aegis_lsm.bpf.c")
    set(BPF_OBJ "${CMAKE_BINARY_DIR}/aegis_lsm.bpf.o")
    set(BPF_SKEL "${CMAKE_BINARY_DIR}/aegis_lsm.skel.h")

    add_custom_command(
        OUTPUT ${BPF_OBJ}
        COMMAND ${CLANG} -g -O2 -target bpf
            -D__TARGET_ARCH_${ARCH}
            -I${CMAKE_SOURCE_DIR}/src/bpf
            -I${CMAKE_SOURCE_DIR}/vmlinux
            -c ${BPF_SRC} -o ${BPF_OBJ}
        DEPENDS ${BPF_SRC}
        COMMENT "Compiling eBPF program"
    )

    add_custom_command(
        OUTPUT ${BPF_SKEL}
        COMMAND ${BPFTOOL} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
        DEPENDS ${BPF_OBJ}
        COMMENT "Generating BPF skeleton header"
    )

    add_custom_target(bpf_skeleton DEPENDS ${BPF_SKEL})
endif()

# --- Daemon sources ---
set(DAEMON_SOURCES
    src/daemon/main.cpp
    src/daemon/ipc_server.cpp
    src/daemon/database.cpp
    src/daemon/policy_engine.cpp
    src/daemon/typosquat.cpp
    src/daemon/http_client.cpp
    src/daemon/agent_monitor.cpp
    src/daemon/signal_handler.cpp
)

if(AEGIS_ENABLE_BPF)
    list(APPEND DAEMON_SOURCES src/daemon/bpf_manager.cpp)
endif()

add_executable(aegisd ${DAEMON_SOURCES})

target_include_directories(aegisd PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
    ${YAML_CPP_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
    ${LIBCURL_INCLUDE_DIRS}
)

target_link_libraries(aegisd PRIVATE
    ${YAML_CPP_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    ${LIBCURL_LIBRARIES}
    pthread
)

if(AEGIS_ENABLE_BPF)
    add_dependencies(aegisd bpf_skeleton)
    target_compile_definitions(aegisd PRIVATE AEGIS_BPF_ENABLED)
    target_include_directories(aegisd PRIVATE
        ${LIBBPF_INCLUDE_DIRS}
        ${LIBELF_INCLUDE_DIRS}
    )
    target_link_libraries(aegisd PRIVATE
        ${LIBBPF_LIBRARIES}
        ${LIBELF_LIBRARIES}
        ${ZLIB_LIBRARIES}
    )
endif()

# --- Install ---
install(TARGETS aegisd RUNTIME DESTINATION bin)
install(FILES etc/aegis-default.yml DESTINATION etc/aegis RENAME config.yml)
install(FILES etc/aegisd.service DESTINATION lib/systemd/system)

# --- Tests (optional) ---
if(AEGIS_ENABLE_TESTS)
    enable_testing()
    find_package(GTest QUIET)

    if(GTest_FOUND)
        # Library for testing (without main.cpp)
        add_library(aegisd_lib STATIC
            src/daemon/ipc_server.cpp
            src/daemon/database.cpp
            src/daemon/policy_engine.cpp
            src/daemon/typosquat.cpp
            src/daemon/http_client.cpp
            src/daemon/agent_monitor.cpp
            src/daemon/signal_handler.cpp
        )
        target_include_directories(aegisd_lib PUBLIC
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_BINARY_DIR}
            ${YAML_CPP_INCLUDE_DIRS}
            ${SQLITE3_INCLUDE_DIRS}
            ${LIBCURL_INCLUDE_DIRS}
        )
        target_link_libraries(aegisd_lib PUBLIC
            ${YAML_CPP_LIBRARIES}
            ${SQLITE3_LIBRARIES}
            ${LIBCURL_LIBRARIES}
            pthread
        )

        add_executable(test_typosquat tests/test_typosquat.cpp)
        target_link_libraries(test_typosquat PRIVATE aegisd_lib GTest::gtest_main)
        add_test(NAME typosquat COMMAND test_typosquat)

        add_executable(test_policy_engine tests/test_policy_engine.cpp)
        target_link_libraries(test_policy_engine PRIVATE aegisd_lib GTest::gtest_main)
        add_test(NAME policy_engine COMMAND test_policy_engine)

        add_executable(test_ipc tests/test_ipc.cpp)
        target_link_libraries(test_ipc PRIVATE aegisd_lib GTest::gtest_main)
        add_test(NAME ipc COMMAND test_ipc)
    else()
        message(STATUS "GTest not found, skipping C++ tests")
    endif()
endif()
