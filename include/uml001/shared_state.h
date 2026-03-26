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

#include <cstdint>
#include <string>
#include <vector>

namespace uml001 {

/**
 * @brief POD snapshot of the BFT clock state for Redis promotion.
 */
struct SharedClockState {
    uint64_t last_agreed_time_ms = 0;
    double   current_drift_ppm = 0.0;
    uint64_t version_counter = 0;      // For optimistic concurrency
    char     active_signer_id[64] = {0};
    
    // Serializes state for Redis storage
    std::string serialize() const {
        return std::string(reinterpret_cast<const char*>(this), sizeof(SharedClockState));
    }

    static SharedClockState deserialize(const std::string& data) {
        SharedClockState state;
        if (data.size() == sizeof(SharedClockState)) {
            fallback_memcpy(&state, data.data(), sizeof(SharedClockState));
        }
        return state;
    }

private:
    static void fallback_memcpy(void* dest, const void* src, size_t n) {
        auto d = static_cast<char*>(dest);
        auto s = static_cast<const char*>(src);
        while (n--) *d++ = *s++;
    }
};

} // namespace uml001