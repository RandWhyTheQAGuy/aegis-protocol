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

namespace uml001 {

enum class TemporalState {
    SYNCHRONIZED,
    CACHED,
    DEGRADED,
    UNTRUSTED
};

class TemporalStateMachine {
public:
    void update(uint64_t time_since_last_quorum_ms)
    {
        if (time_since_last_quorum_ms < 100)
            state_ = TemporalState::SYNCHRONIZED;
        else if (time_since_last_quorum_ms < 2000)
            state_ = TemporalState::CACHED;
        else if (time_since_last_quorum_ms < 10000)
            state_ = TemporalState::DEGRADED;
        else
            state_ = TemporalState::UNTRUSTED;
    }

    TemporalState state() const { return state_; }

    bool allow_writes() const
    {
        return state_ == TemporalState::SYNCHRONIZED ||
               state_ == TemporalState::CACHED;
    }

    bool allow_reads() const
    {
        return state_ != TemporalState::UNTRUSTED;
    }

private:
    TemporalState state_{TemporalState::UNTRUSTED};
};

} // namespace uml001