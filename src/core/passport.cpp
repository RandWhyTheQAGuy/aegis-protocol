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

static std::string vec_to_str(const std::vector<uint8_t>& vec) {
    return std::string(vec.begin(), vec.end());
}

// -------------------- Passport --------------------
void Passport::issue(std::shared_ptr<IClock> clock, uint64_t duration_sec) {
    if (!clock) {
        throw std::runtime_error("Cannot issue passport without a trusted clock.");
    }

    this->issued_at = clock->now_unix();
    this->expires_at = this->issued_at + duration_sec;
    this->status = PassportStatus::ACTIVE;
}

// -------------------- PassportRegistry --------------------
Passport PassportRegistry::issue_model_passport(
    const std::string& model_id,
    const std::string& version,
    const Capabilities& caps,
    const std::string& policy_hash,
    uint32_t key_id
) {
    Passport p;
    p.model_id       = model_id;
    p.model_version  = version;
    p.capabilities   = caps;
    p.policy_hash    = policy_hash;
    p.signing_key_id = key_id;
    p.registry_version = "1.2.0";

    // 1. Retrieve signing material from Vault
    auto key_opt = vault_.retrieve(std::to_string(key_id));
    if (!key_opt) {
        throw std::runtime_error("Vault Error: Signing key " + std::to_string(key_id) + " not found.");
    }
    p.signing_key_material = vec_to_str(*key_opt);

    // 2. Establish BFT Issuance Time
    p.issue(std::shared_ptr<IClock>(&clock_, [](IClock*){}), 86400);

    // 3. 🛠 STEP 3: Cryptographic Anchoring
    // We append the intent to issue to the log first to get a new Merkle Root.
    log_.append(
        TransparencyEntry::Type::PASSPORT_ISSUED,
        "PASSPORT_PROPOSAL",
        sha256_hex(model_id + version + policy_hash),
        std::to_string(key_id),
        "BFT_TIME=" + std::to_string(p.issued_at)
    );

    // Capture the state of the log at this exact moment
    p.log_root_hash = log_.get_root_hash();

    // 4. Final Signature
    // The HMAC now covers the log_root_hash via p.content_hash()
    p.signature = hmac_sha256_hex(
        p.signing_key_material,
        p.content_hash()
    );

    std::cout << "[Aegis] Passport Anchored to Log Root: " 
              << p.log_root_hash.substr(0, 12) << "..." << std::endl;

    return p;
}

// -------------------- Verification --------------------
VerifyResult PassportRegistry::verify(const Passport& passport) const {
    VerifyResult result;
    uint64_t now = clock_.now_unix();

    // Time Check
    if (passport.expires_at < now) {
        result.status = VerifyStatus::EXPIRED;
        return result;
    }

    // Status Check
    if (passport.status != PassportStatus::ACTIVE) {
        result.status = VerifyStatus::INCOMPATIBLE;
        return result;
    }

    // Revocation Check
    if (revocation_list_.is_revoked(passport.model_id)) {
        result.status = VerifyStatus::REVOKED;
        return result;
    }

    // 🛠 STEP 3: Log Anchor Check
    // Verification fails if the passport references a root that doesn't exist in our log
    // Note: In a distributed system, this might check a local cache of known roots.
    if (passport.log_root_hash.empty()) {
        result.status = VerifyStatus::LOG_MISMATCH;
        return result;
    }

    // Cryptographic Signature Check
    auto internal_key_opt = vault_.retrieve(std::to_string(passport.signing_key_id));
    if (!internal_key_opt) {
        result.status = VerifyStatus::INVALID_SIGNATURE; 
        return result;
    }

    std::string expected_sig = hmac_sha256_hex(
        vec_to_str(*internal_key_opt),
        passport.content_hash()
    );

    if (expected_sig != passport.signature) {
        result.status = VerifyStatus::INVALID_SIGNATURE;
        return result;
    }

    result.status = VerifyStatus::OK;
    result.verified_key_id = passport.signing_key_id;
    result.recovered = passport.is_recovered();
    result.confidence = 1.0f;

    return result;
}

} // namespace uml001