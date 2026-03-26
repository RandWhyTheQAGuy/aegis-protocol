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

#pragma once

#include "uml001/shared_state.h"
#include <optional>

namespace uml001 {

/**
 * @brief Abstract interface for clock state backends (Redis, memory, etc.).
 */
class IClockStore {
public:
    virtual ~IClockStore() = default;

    /**
     * @brief Atomically attempts to promote a new shared clock state.
     * @return true if the promotion succeeded (no conflicting concurrent write).
     */
    virtual bool watch_and_commit(const SharedClockState& new_state) = 0;

    /**
     * @brief Fetches the latest known shared clock state, if any.
     */
    virtual std::optional<SharedClockState> get_latest_state() = 0;
};

} // namespace uml001
