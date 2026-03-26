/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Gary Gray (github.com/<your-github-handle>)
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
#include "uml001/memory_clock_store.h"

namespace uml001 {

bool MemoryClockStore::watch_and_commit(const SharedClockState& new_state) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_) {
        // Preserve optimistic concurrency semantics: reject stale updates.
        if (new_state.version_counter <= state_->version_counter) {
            return false;
        }
    }

    state_ = new_state;
    return true;
}

std::optional<SharedClockState> MemoryClockStore::get_latest_state() {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

} // namespace uml001
