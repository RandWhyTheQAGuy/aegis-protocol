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
#include <optional>
#include <cstdint>
#include <memory>

namespace uml001 {

// Forward declarations to break circular dependencies
class IClock;
class TransparencyLog;
class RevocationList;

enum class PassportStatus {
    INACTIVE,
    ACTIVE,
    REVOKED
};

enum class VerifyStatus {
    OK = 0,
    EXPIRED = 1,
    REVOKED = 2,
    INVALID_SIGNATURE = 3,
    INCOMPATIBLE = 4
};

struct VerifyResult {
    VerifyStatus status = VerifyStatus::OK;
    uint32_t verified_key_id = 0;
    bool recovered = false;
    float confidence = 0.0f;

    bool ok() const {
        return status == VerifyStatus::OK;
    }

    std::string status_str() const {
        switch (status) {
            case VerifyStatus::OK: return "OK";
            case VerifyStatus::EXPIRED: return "EXPIRED";
            case VerifyStatus::REVOKED: return "REVOKED";
            case VerifyStatus::INVALID_SIGNATURE: return "INVALID_SIGNATURE";
            case VerifyStatus::INCOMPATIBLE: return "INCOMPATIBLE";
            default: return "UNKNOWN";
        }
    }
};

struct Capabilities {
    bool classifier_authority = false;
    bool classifier_sensitivity = false;
    bool bft_consensus = false;
    bool entropy_flush = false;

    std::string serialize() const {
        return std::string(classifier_authority ? "1" : "0") +
               std::string(classifier_sensitivity ? "1" : "0") +
               std::string(bft_consensus ? "1" : "0") +
               std::string(entropy_flush ? "1" : "0");
    }
};

struct Passport {
    std::string model_id;
    std::string model_version;
    Capabilities capabilities;
    std::string policy_hash;

    uint64_t issued_at = 0;
    uint64_t expires_at = 0;
    PassportStatus status = PassportStatus::INACTIVE;

    uint32_t signing_key_id = 0;
    std::string signature;
    std::optional<std::string> recovery_token;

    std::string signing_key_material;
    std::string registry_version;

    bool is_recovered() const {
        return recovery_token.has_value();
    }

    bool is_valid(uint64_t now) const {
        return status == PassportStatus::ACTIVE &&
               now >= issued_at &&
               now < expires_at;
    }

    std::string canonical_body() const {
        return model_id + "|" + model_version + "|" +
               capabilities.serialize() + "|" +
               policy_hash + "|" +
               std::to_string(issued_at) + "|" +
               std::to_string(expires_at) + "|" +
               registry_version;
    }

    void issue(std::shared_ptr<IClock> clock, uint64_t duration_sec = 3600);

    std::string content_hash() const {
        std::string raw = model_id + "|" + model_version + "|" +
                          capabilities.serialize() + "|" +
                          policy_hash + "|" +
                          std::to_string(issued_at) + "|" +
                          std::to_string(expires_at);
        return sha256_hex(raw);
    }
};

class PassportRegistry {
public:
    PassportRegistry(TransparencyLog& log,
                     RevocationList& list,
                     IClock& clock)
        : log_(log), revocation_list_(list), clock_(clock) {}

    Passport issue_model_passport(
        const std::string& model_id,
        const std::string& version,
        const Capabilities& caps,
        const std::string& policy_hash,
        uint32_t key_id
    );

    VerifyResult verify(const Passport& passport) const;

private:
    TransparencyLog& log_;
    RevocationList&  revocation_list_;
    IClock&          clock_;
};

} // namespace uml001