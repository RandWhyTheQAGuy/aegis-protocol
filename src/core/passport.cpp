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
#include "uml001/core/passport.h"
#include "uml001/security/transparency_log.h"
#include "uml001/security/revocation.h"
#include "uml001/core/clock.h"
#include "uml001/crypto/crypto_utils.h"

#include <iostream>
#include <stdexcept>

using uml001::hmac_sha256_hex;

namespace uml001 {

// -------------------- Passport --------------------
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
    p.signing_key_material = "default-signing-key"; // TODO: replace with vault/HSM
    p.registry_version = "0.1.0";

    // Use canonical issuance path
    p.issue(std::shared_ptr<IClock>(&clock_, [](IClock*){}), 86400);

    // Sign AFTER issuance fields are set
    p.signature = hmac_sha256_hex(
        p.signing_key_material,
        p.content_hash()
    );

    // Append to transparency log
    log_.append(
        TransparencyEntry::Type::PASSPORT_ISSUED,
        "PASSPORT_ISSUED",
        p.content_hash(),
        std::to_string(key_id)
    );

    return p;
}

// -------------------- Verification --------------------
VerifyResult PassportRegistry::verify(const Passport& passport) const {
    VerifyResult result;

    uint64_t now = clock_.now_unix();

    // 1. Expiry check
    if (passport.expires_at < now) {
        result.status = VerifyStatus::EXPIRED;
        return result;
    }

    // 2. Status check
    if (passport.status != PassportStatus::ACTIVE) {
        result.status = VerifyStatus::INCOMPATIBLE;
        return result;
    }

    // 3. Revocation check (CRITICAL FIX)
    if (revocation_list_.is_revoked(passport.model_id)) {
        result.status = VerifyStatus::REVOKED;
        return result;
    }

    // 4. Signature verification (CRITICAL FIX)
    std::string expected_sig = hmac_sha256_hex(
        passport.signing_key_material,
        passport.content_hash()
    );

    if (expected_sig != passport.signature) {
        result.status = VerifyStatus::INVALID_SIGNATURE;
        return result;
    }

    // 5. Success
    result.status = VerifyStatus::OK;
    result.verified_key_id = passport.signing_key_id;
    result.recovered = passport.is_recovered();
    result.confidence = 1.0f;

    return result;
}

} // namespace uml001