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
#include <atomic>
#include <chrono>

namespace uml001 {

/**
 * @brief High-precision local clock used as the foundation for BFT drift calculations.
 */
class OsStrongClock : public IClock {
public:
    OsStrongClock();

    uint64_t now_unix() const override;
    uint64_t now_ms() const override;
    bool is_synchronized() const override { return synchronized_.load(); }
    uint64_t last_sync_unix() const override { return last_sync_.load(); }
    ClockStatus status() const override;
    std::string source_id() const override { return "OS_SYSTEM_STRONG"; }

    // Internal update for the background sync loop
    void mark_synchronized(bool sync);

private:
    std::atomic<bool> synchronized_;
    std::atomic<uint64_t> last_sync_;
};

} // namespace uml001