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
#include "uml001/globals.h"
#include <mutex>
#include <stdexcept>

namespace uml001 {

// Global state (protected by mutex for thread-safety)
static std::mutex g_clock_mutex;
static std::shared_ptr<IClock> g_clock;

void init_clock(std::shared_ptr<IClock> clock) {
    std::lock_guard<std::mutex> lock(g_clock_mutex);
    if (!clock) {
        throw std::invalid_argument("Clock instance cannot be null");
    }
    g_clock = clock;
}

std::shared_ptr<IClock> get_clock() {
    std::lock_guard<std::mutex> lock(g_clock_mutex);
    if (!g_clock) {
        throw std::runtime_error("Global clock not initialized. Call init_clock() first.");
    }
    return g_clock;
}

uint64_t now_unix() {
    return get_clock()->now_unix();
}

bool validate_timestamp(uint64_t timestamp_unix) {
    auto clock = get_clock();
    uint64_t current = clock->now_unix();
    
    // Reject timestamps in the future or too far in the past
    static constexpr uint64_t MAX_SKEW_SECONDS = 3600; // 1 hour
    
    if (timestamp_unix > current + MAX_SKEW_SECONDS) {
        return false; // Timestamp is too far in the future
    }
    
    // Allow up to 100 years in the past (to avoid issues with recent epoch times)
    uint64_t min_allowed = (current > MAX_SKEW_SECONDS * 365 * 24 * 100) ? 
                           (current - MAX_SKEW_SECONDS * 365 * 24 * 100) : 0;
    if (timestamp_unix < min_allowed) {
        return false;
    }
    
    return true;
}

} // namespace uml001
