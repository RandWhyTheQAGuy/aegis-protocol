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
#include <memory>

namespace uml001 {

class IClock;

// --------------------
// Supporting Types
// --------------------

struct Capabilities {
    bool classifier_authority = false;
    bool classifier_sensitivity = false;
    bool bft_consensus = false;
    bool entropy_flush = false;
};

enum class PassportStatus {
    IDLE,
    ACTIVE,
    REVOKED,
    EXPIRED
};

enum class VerifyStatus {
    OK,
    EXPIRED,
    REVOKED,
    INVALID_SIGNATURE,
    LOG_MISMATCH,
    INSUFFICIENT_QUORUM,
    INCOMPATIBLE
};

struct VerifyResult {
    VerifyStatus status = VerifyStatus::INCOMPATIBLE;
    uint32_t verified_key_id = 0;
    bool recovered = false;
    float confidence = 0.0f;
};

struct QuorumProof {
    uint32_t threshold = 0;
    std::vector<uint32_t> signer_ids;
    std::vector<std::string> signatures;
    std::string root_signature;

    bool is_complete() const {
        return signatures.size() >= threshold && threshold > 0;
    }
};

// --------------------
// Passport Struct
// --------------------

struct Passport {
    std::string model_id;
    std::string model_version;
    std::string registry_version;
    
    uint64_t issued_at = 0;
    uint64_t expires_at = 0;
    
    Capabilities capabilities;
    std::string policy_hash;
    std::string log_root_hash;
    
    PassportStatus status = PassportStatus::IDLE;
    uint32_t signing_key_id = 0;
    std::string signing_key_material; // For HMAC-based legacy flows
    std::string signature;
    
    QuorumProof proof;

    void issue(std::shared_ptr<IClock> clock, uint64_t duration_sec);
    
    std::string content_hash() const {
        return sha256_hex(model_id + "|" + model_version + "|" + std::to_string(issued_at) + "|" + policy_hash);
    }

    bool is_recovered() const { return false; } // Placeholder for state recovery logic
};

} // namespace uml001