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

#include "uml001/crypto/crypto_utils.h"
#include <string>
#include <vector>
#include <map>

namespace uml001 {

struct Passport {
    std::string passport_id;
    std::string subject_id;
    std::string issuer_id;
    uint64_t    issued_at = 0;
    uint64_t    expires_at = 0;
    
    std::map<std::string, std::string> attributes;
    std::vector<std::string> roles;
    std::vector<std::string> permissions;
    
    std::string signature_hex;

    std::string content_hash() const {
        return sha256_hex(subject_id + "|" + std::to_string(issued_at) + "|" + issuer_id);
    }
};

class PassportRegistry {
public:
    PassportRegistry(class TransparencyLog& log, class RevocationList& list, class IClock& clock)
        : log_(log), revocation_list_(list), clock_(clock) {}

    Passport issue(const std::string& subject_id, 
                   const std::map<std::string, std::string>& attrs,
                   const std::string& issuer_id);
    
    bool verify(const Passport& passport);

private:
    class TransparencyLog& log_;
    class RevocationList&  revocation_list_;
    class IClock&          clock_;
};

}