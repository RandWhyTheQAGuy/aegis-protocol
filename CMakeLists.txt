cmake_minimum_required(VERSION 3.20)
project(UML001 VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# Dependencies
# ============================================================
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ============================================================
# Proto Generation (v1.2: Pointing to Quorum Time Repo)
# ============================================================
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../quorum_time/proto/clock_service.proto)

get_filename_component(PROTO_DIR ${PROTO_FILE} PATH)
get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)

set(PROTO_SRC ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.cc)
set(PROTO_HDR ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.h)
set(GRPC_SRC  ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.cc)
set(GRPC_HDR  ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.h)

find_program(PROTOC_EXECUTABLE protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

# 🛠 RE-ADDED: The command that actually generates the .h and .cc files
add_custom_command(
    OUTPUT ${PROTO_SRC} ${PROTO_HDR} ${GRPC_SRC} ${GRPC_HDR}
    COMMAND ${PROTOC_EXECUTABLE}
    ARGS --proto_path=${PROTO_DIR}
         --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
         --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
         --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
         ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
)

# 🛠 RE-ADDED: The library that wraps the generated code
add_library(clock_proto STATIC ${PROTO_SRC} ${GRPC_SRC})
target_include_directories(clock_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(clock_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)

# ============================================================
# Include Paths
# ============================================================
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR} # 🛠 FIX: Allows finding clock_service.grpc.pb.h
)

# ============================================================
# UML001 CORE
# ============================================================
set(UML001_CORE_SOURCES
    src/core/passport.cpp
    src/core/policy.cpp
    src/core/session.cpp
    src/core/temporal_state.cpp
    src/core/pulse_manager.cpp
    src/core/quorum_pulse_manager.cpp
    src/core/registry.cpp
    src/security/transparency_log.cpp
    src/security/revocation.cpp
    src/security/key_manager.cpp
    src/security/vault.cpp
    src/crypto/crypto_utils.cpp
    src/crypto/crypto_facade.cpp
    src/crypto/hash_provider.cpp
    src/crypto/simple_hash_provider.cpp
    src/bft/remote_quorum_clock.cpp
    src/bft_clock_client.cpp
    src/sidecar/aegis_guard.cpp
    src/classifier.cpp
    src/providers/datadog_logger.cpp
    src/providers/memory_clock_store.cpp
)

add_library(uml001_core STATIC ${UML001_CORE_SOURCES})

# 🛠 FIX: Call add_dependencies AFTER the library is created
add_dependencies(uml001_core clock_proto)

target_link_libraries(uml001_core
    PUBLIC
    clock_proto
    OpenSSL::Crypto
    OpenSSL::SSL
    Threads::Threads
    gRPC::grpc++
)

# ============================================================
# EXECUTABLES
# ============================================================
add_executable(aegis_daemon src/main_aegis_protocol.cpp)
target_link_libraries(aegis_daemon PRIVATE uml001_core)

add_executable(test_passport_flow tests/test_passport_flow.cpp)
target_link_libraries(test_passport_flow PRIVATE uml001_core)