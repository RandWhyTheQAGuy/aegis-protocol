/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * The Aegis Protocol defines a distributed trust and identity framework
 * based on cryptographically verifiable Semantic Passports, capability
 * enforcement, and transparency logging for auditable system behavior.
 *
 * Core components include:
 *   - Semantic Passports: verifiable identity and capability attestations
 *   - Transparency Log: append-only cryptographic audit trail of system events
 *   - Revocation System: deterministic invalidation of compromised or expired identities
 *   - Passport Registry: issuance and verification authority for trusted entities
 *
 * This framework is designed for open standardization, interoperability,
 * and production-grade use in distributed identity, AI systems, and
 * verifiable authorization infrastructures.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for research, verifiable systems design,
 * and deployment in security-critical distributed environments.
 */
#pragma once

/**
 * @file platform.h
 * @brief Minimal socket portability layer for BftClockClient.
 *
 * Abstracts the differences between POSIX (AF_UNIX) and Windows (named pipe)
 * socket types so bft_clock_client.h and bft_clock_client.cpp can reference
 * a single consistent set of types and helpers.
 */

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   using socket_t = SOCKET;
   static constexpr socket_t SOCKET_INVALID = INVALID_SOCKET;
   inline void close_socket(socket_t s) { closesocket(s); }
#else
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <netinet/in.h>
   using socket_t = int;
   static constexpr socket_t SOCKET_INVALID = -1;
   inline void close_socket(socket_t s) { ::close(s); }
#endif

#include <cstdint>
#include <string>
#include <stdexcept>
#include <chrono>

namespace uml001 {

/**
 * @brief Set a receive timeout on a socket.
 * @param s       Socket descriptor.
 * @param ms      Timeout in milliseconds. 0 = no timeout.
 * @throws std::runtime_error on failure.
 */
inline void set_recv_timeout(socket_t s, uint64_t ms) {
#ifdef _WIN32
    DWORD timeout = static_cast<DWORD>(ms);
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout),
                   sizeof(timeout)) != 0)
        throw std::runtime_error("set_recv_timeout: setsockopt failed");
#else
    struct timeval tv;
    tv.tv_sec  = static_cast<long>(ms / 1000);
    tv.tv_usec = static_cast<long>((ms % 1000) * 1000);
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof(tv)) != 0)
        throw std::runtime_error("set_recv_timeout: setsockopt failed");
#endif
}

/**
 * @brief Set a connect timeout on a socket (non-blocking connect + select).
 * @param s       Socket descriptor.
 * @param ms      Timeout in milliseconds.
 */
inline void set_connect_timeout(socket_t s, uint64_t ms) {
#ifdef _WIN32
    // Windows: use non-blocking mode + WSAWaitForMultipleEvents
    // Simplified: just set SO_SNDTIMEO
    DWORD timeout = static_cast<DWORD>(ms);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    // POSIX: set SO_SNDTIMEO; caller does non-blocking connect + select
    struct timeval tv;
    tv.tv_sec  = static_cast<long>(ms / 1000);
    tv.tv_usec = static_cast<long>((ms % 1000) * 1000);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

} // namespace uml001