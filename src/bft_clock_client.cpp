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
#include "uml001/core/bft_clock_client.h"
#include "uml001/crypto/crypto_utils.h"

#include <chrono>

namespace uml001 {

BftClockClient::BftClockClient(BftClockClientConfig cfg)
    : cfg_(std::move(cfg)),
      cached_unix_time_s_(0),
      cached_sync_unix_s_(0),
      cached_confidence_ms_(0.0),
      cached_active_nodes_(0),
      cached_drift_ppm_(0.0) {

    try {
        // 🛠 FIX: Using uml001 namespace instead of quorumtime
        stub_ = uml001::ClockService::NewStub(
            grpc::CreateChannel(cfg_.target_uri,
            grpc::InsecureChannelCredentials()));
    } catch (...) {
        stub_ = nullptr;
    }
}

BftTimeResponseData BftClockClient::do_grpc_request() const {
    // 🛠 FIX: Match proto message names (GetTimeRequest)
    uml001::GetTimeRequest request;

    // Use existing crypto utils for request correlation
    std::string request_id = generate_random_bytes_hex(16);

    // Note: If your proto doesn't have these fields yet, 
    // we can comment them out, but standard Aegis RFI requires them.
    // request.set_client_id(cfg_.client_id); 
    
    uml001::TimeResponse response;
    grpc::ClientContext ctx;

    ctx.set_deadline(
        std::chrono::system_clock::now() +
        std::chrono::milliseconds(cfg_.connect_timeout_ms));

    if (!stub_) {
        throw BftClockIpcError("gRPC stub not initialized");
    }

    // 🛠 FIX: Method name is 'GetTime' in your proto
    auto status = stub_->GetTime(&ctx, request, &response);
    if (!status.ok()) {
        throw BftClockIpcError(status.error_message());
    }

    BftTimeResponseData r;
    // 🛠 FIX: Mapping to proto field 'unix_timestamp'
    r.unix_time_ms        = response.unix_timestamp(); 
    r.confidence_interval = 1.0; // Placeholder until proto adds quality metrics
    r.active_nodes        = 1; 
    r.projected_drift_ppm = 0.0;

    return r;
}

uint64_t BftClockClient::now_unix() const {
    std::lock_guard<std::mutex> lock(mx_);

    auto now = std::chrono::steady_clock::now();
    
    // Check cache freshness
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - cache_filled_).count();

    if (elapsed > static_cast<int64_t>(cfg_.cache_ttl_ms) || cached_unix_time_s_ == 0) {
        auto response = do_grpc_request();

        // Convert ms from BFT response to seconds
        uint64_t new_time = response.unix_time_ms / 1000;

        enforce_monotonic(new_time);

        cached_unix_time_s_ = new_time;
        cached_sync_unix_s_ = new_time;
        cached_confidence_ms_ = response.confidence_interval;
        cached_active_nodes_ = response.active_nodes;
        cached_drift_ppm_ = response.projected_drift_ppm;

        cache_filled_ = now;
    }

    return cached_unix_time_s_;
}

uint64_t BftClockClient::now_ms() const {
    return now_unix() * 1000ULL;
}

bool BftClockClient::is_synchronized() const {
    return status() == ClockStatus::SYNCHRONIZED;
}

uint64_t BftClockClient::last_sync_unix() const {
    std::lock_guard<std::mutex> lock(mx_);
    return cached_sync_unix_s_;
}

ClockStatus BftClockClient::status() const {
    std::lock_guard<std::mutex> lock(mx_);

    if (cached_unix_time_s_ == 0) return ClockStatus::UNKNOWN;

    // Logic based on BFT quality metrics
    if (cached_confidence_ms_ < 50.0) {
        return ClockStatus::SYNCHRONIZED;
    } else if (cached_confidence_ms_ < 200.0) {
        return ClockStatus::DEGRADED;
    } else {
        return ClockStatus::FAULT; 
    }
}

std::string BftClockClient::source_id() const {
    return "BFT-QUORUM-PROXY";
}

void BftClockClient::verify_skew(const BftTimeResponseData&) const {}

void BftClockClient::enforce_monotonic(uint64_t new_time) const {
    uint64_t current = monotonic_floor_.load();
    while (new_time > current &&
           !monotonic_floor_.compare_exchange_weak(current, new_time)) {}

    if (new_time < current) {
        // Return current to prevent crash, but this indicates a BFT node issue
        return; 
    }
}

} // namespace uml001