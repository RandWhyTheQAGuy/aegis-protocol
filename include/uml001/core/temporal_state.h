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

namespace uml001 {

/**
 * @brief TemporalState reflects the BFT Quorum health.
 */
enum class TemporalState {
    SYNCHRONIZED, ///< Quorum reached, uncertainty < 50ms
    CACHED,       ///< IPC alive, but relying on local drift (Uncertainty 50-200ms)
    DEGRADED,     ///< Drift/Skew exceeding safety window (Uncertainty > 200ms)
    UNTRUSTED     ///< Quorum lost or Signature mismatch. STOP ALL OPS.
};

class TemporalStateMachine {
public:
    TemporalStateMachine() : current_state_(TemporalState::UNTRUSTED) {}

    /**
     * @brief Updates state based on BFT metrics from the sidecar.
     * @param uncertainty_ms The current confidence interval from the Quorum.
     * @param drift_ppm The parts-per-million drift of the local oscillator.
     */
    void update(double uncertainty_ms, double drift_ppm) {
        if (uncertainty_ms < 50.0 && drift_ppm < 100.0) {
            current_state_ = TemporalState::SYNCHRONIZED;
        } else if (uncertainty_ms < 200.0) {
            current_state_ = TemporalState::CACHED;
        } else if (uncertainty_ms < 1000.0 || drift_ppm > 500.0) {
            current_state_ = TemporalState::DEGRADED;
        } else {
            current_state_ = TemporalState::UNTRUSTED;
        }
    }

    TemporalState state() const { return current_state_; }

    static std::string state_str(TemporalState s) {
        switch (s) {
            case TemporalState::SYNCHRONIZED: return "SYNCHRONIZED";
            case TemporalState::CACHED:       return "CACHED";
            case TemporalState::DEGRADED:     return "DEGRADED";
            case TemporalState::UNTRUSTED:    return "UNTRUSTED";
            default:                          return "UNKNOWN";
        }
    }

private:
    TemporalState current_state_;
};

} // namespace uml001