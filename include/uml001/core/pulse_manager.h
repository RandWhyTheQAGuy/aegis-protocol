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

#include "uml001/core/clock.h"
#include "uml001/core/temporal_state.h"
#include <thread>
#include <atomic>

namespace uml001 {

/**
 * @brief PulseManager maintains the heartbeat of the BFT Quorum connection.
 * It periodically polls the clock and updates the TemporalStateMachine.
 * * [E-3] "Connected Integrity": Validates that the Quorum clock is still responsive.
 */
class PulseManager {
public:
    explicit PulseManager(IClock& clock);
    ~PulseManager();

    void start();
    void stop();

    TemporalState current_state() const;

private:
    void loop();
    uint64_t now_ms() const;

    IClock& clock_;
    TemporalStateMachine tsm_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    uint64_t last_success_{0};
};

} // namespace uml001