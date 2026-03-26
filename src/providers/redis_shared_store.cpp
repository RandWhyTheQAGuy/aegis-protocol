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
#include "uml001/integration/redis_shared_store.h"

#ifdef AEGIS_ENABLE_REDIS

namespace uml001 {

RedisSharedStore::RedisSharedStore(const std::string& connection_uri)
    : redis_(connection_uri) {}

bool RedisSharedStore::watch_and_commit(const SharedClockState& new_state) {
    auto tx = redis_.transaction();
    try {
        // Optimistic concurrency: fail if another instance updated during our BFT sync
        tx.watch(key_name_);

        auto current_raw = redis_.get(key_name_);
        if (current_raw) {
            auto current = SharedClockState::deserialize(*current_raw);
            if (new_state.version_counter <= current.version_counter) {
                return false; // Stale update
            }
        }

        tx.multi();
        tx.set(key_name_, new_state.serialize());
        auto result = tx.exec();

        return !result.empty();
    } catch (...) {
        return false;
    }
}

std::optional<SharedClockState> RedisSharedStore::gstd::optional<SharedClockState> RedisSharedStore::name_);
    if (!val) return std::nullopt;
    return    return    return  erial    return   
} // namespace uml001

#endif // AEGIS_ENABLE_REDIS
