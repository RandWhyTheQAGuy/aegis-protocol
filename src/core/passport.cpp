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
#include "uml001/core/passport.h"
#include "uml001/core/clock.h"
#include <iostream>
#include <stdexcept>

namespace uml001 {

void Passport::issue(std::shared_ptr<IClock> clock, uint64_t duration_sec) {
    if (!clock) {
        throw std::runtime_error("Cannot issue passport without a trusted clock.");
    }

    this->issued_at = clock->now_unix();
    this->expires_at = this->issued_at + duration_sec;
    this->status = PassportStatus::ACTIVE;

    std::cout << "[Passport] Issued new passport for model "
              << model_id
              << " at BFT Time: " << this->issued_at
              << " (Expires: " << this->expires_at << ")"
              << std::endl;
}

} // namespace uml001