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

#include "uml001/clock.h"
#include "clock_service.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace uml001 {

/**
 * @brief Exception for BFT clock IPC failures
 */
class BftClockIpcError : public std::runtime_error {
public:
    explicit BftClockIpcError(const std::string& m)
        : std::runtime_error("BFT_GRPC: " + m) {}
};

/**
 * @brief Runtime configuration for the BFT clock client
 */
struct BftClockClientConfig {
    std::string target_uri = "unix:///var/run/uml001/bft-clock.sock";

    std::string client_id = "aegis";

    uint64_t max_skew_s         = 5;
    uint64_t connect_timeout_ms = 2000;
    uint64_t cache_ttl_ms       = 200;

    bool fail_closed = true;
};

/**
 * @brief Parsed response from quorum service
 */
struct BftTimeResponseData {
    uint64_t unix_time_ms        = 0;
    double   confidence_interval = 0.0;
    int32_t  active_nodes        = 0;
    double   projected_drift_ppm = 0.0;
};

/**
 * @brief gRPC-backed BFT clock client with caching + safety enforcement
 */
class BftClockClient : public IClock {
public:
    explicit BftClockClient(BftClockClientConfig cfg);
    ~BftClockClient() override = default;

    /**
     * @brief Returns UNIX time in seconds
     */
    uint64_t now_unix() const override;

    /**
     * @brief Returns UNIX time in milliseconds
     */
    uint64_t now_ms() const override;

    /**
     * @brief Health / state
     */
    bool is_synchronized() const override;
    uint64_t last_sync_unix() const override;
    ClockStatus status() const override;
    std::string source_id() const override;

private:
    BftTimeResponseData do_grpc_request() const;

    void verify_skew(const BftTimeResponseData& r) const;
    void enforce_monotonic(uint64_t new_time) const;

private:
    BftClockClientConfig cfg_;

    std::unique_ptr<quorumtime::ClockService::Stub> stub_;

    mutable std::mutex mx_;

    // Cached values
    mutable uint64_t cached_unix_time_s_{0};
    mutable uint64_t cached_sync_unix_s_{0};
    mutable double   cached_confidence_ms_{0.0};
    mutable int32_t  cached_active_nodes_{0};
    mutable double   cached_drift_ppm_{0.0};

    mutable std::chrono::steady_clock::time_point cache_filled_{};

    // Monotonic floor to prevent rollback attacks
    mutable std::atomic<uint64_t> monotonic_floor_{0};
};

} // namespace uml001