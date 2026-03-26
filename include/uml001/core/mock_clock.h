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

#include "uml001/core/clock.h"

namespace uml001 {

/**
 * @brief Mock clock implementation for CI/CD testing.
 * Provides deterministic timestamps without BFT Quorum dependency.
 */
class MockClock : public IClock {
public:
    MockClock() = default;
    ~MockClock() override = default;

    /**
     * @brief Returns fixed UNIX time in seconds (2025-02-18)
     */
    uint64_t now_unix() const override { 
        return 1740000000ULL; 
    }

    /**
     * @brief Returns fixed UNIX time in milliseconds
     */
    uint64_t now_ms() const override { 
        return 1740000000000ULL; 
    }

    /**
     * @brief Mock clock is always synchronized in testing
     */
    bool is_synchronized() const override {
        return true;
    }

    /**
     * @brief Last sync time (fixed for determinism)
     */
    uint64_t last_sync_unix() const override {
        return 1740000000ULL;
    }

    /**
     * @brief Mock clock is always synchronized in testing
     */
    ClockStatus status() const override { 
        return ClockStatus::SYNCHRONIZED; 
    }

    /**
     * @brief Identifier for this clock source
     */
    std::string source_id() const override {
        return "MockClock-CI";
    }
};

} // namespace uml001
