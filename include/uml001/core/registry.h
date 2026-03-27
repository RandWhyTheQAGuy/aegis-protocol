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

#include "uml001/core/passport.h"
#include <string>
#include <vector>
#include <memory>

namespace uml001 {

class TransparencyLog;
class RevocationList;
class IClock;
class Vault;

/**
 * @brief The Aegis Passport Registry (The Consensus Authority)
 */
class PassportRegistry {
public:
    PassportRegistry(TransparencyLog& log,
                     RevocationList& list,
                     IClock& clock,
                     Vault& vault)
        : log_(log), revocation_list_(list), clock_(clock), vault_(vault) {}

    /**
     * @brief Issues a new model passport with optional quorum requirements.
     */
    Passport issue_model_passport(
        const std::string& model_id,
        const std::string& version,
        const Capabilities& caps,
        const std::string& policy_hash,
        const std::vector<uint32_t>& key_ids,
        uint32_t threshold = 1
    );

    /**
     * @brief Verifies a passport's signature, anchor, and revocation status.
     */
    VerifyResult verify(const Passport& passport) const;

private:
    TransparencyLog& log_;
    RevocationList&  revocation_list_;
    IClock&          clock_;
    Vault&           vault_;
};

} // namespace uml001