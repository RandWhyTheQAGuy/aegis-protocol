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
#include "uml001/core/registry.h"
#include "uml001/core/passport.h"
#include "uml001/core/clock.h"
#include "uml001/security/transparency_log.h"
#include "uml001/security/revocation.h"
#include "uml001/vault.h"

namespace uml001 {

Passport PassportRegistry::issue_model_passport(
    const std::string& model_id,
    const std::string& version,
    const Capabilities& caps,
    const std::string& policy_hash,
    const std::vector<uint32_t>& key_ids,
    uint32_t threshold) 
{
    Passport p;
    p.model_id = model_id;
    p.model_version = version;
    p.capabilities = caps;
    p.policy_hash = policy_hash;
    
    // Temporal Anchoring
    p.issued_at = clock_.now_unix();
    p.expires_at = p.issued_at + 86400; // 24-hour default TTL
    
    // Step 3: Anchor to the current Merkle Tree state
    p.log_root_hash = log_.get_root_hash();

    // Step 4: Quorum Configuration
    p.proof.threshold = threshold;
    p.proof.signer_ids = key_ids;

    std::string hash = p.content_hash();

    // Collect distributed signatures from the Vault
    for (uint32_t id : key_ids) {
        p.proof.signatures.push_back(vault_.sign(id, hash));
    }

    // Record issuance in Transparency Log
    // Mapping: Type, EventStr, PayloadHash, Signer, Metadata, Timestamp
    log_.append(
        TransparencyEntry::Type::PASSPORT_ISSUED, 
        "PASSPORT_ISSUED", 
        hash, 
        "REGISTRY", 
        "model=" + model_id + ";threshold=" + std::to_string(threshold), 
        p.issued_at
    );

    return p;
}

VerifyResult PassportRegistry::verify(const Passport& p) const {
    VerifyResult res;

    // 1. Trust Boundary Validation
    if (!vault_.verify_peer(p.model_id)) {
        res.status = VerifyStatus::INVALID_SIGNATURE; 
        return res;
    }

    // 2. Revocation Status Check
    if (revocation_list_.is_revoked(p.model_id)) {
        res.status = VerifyStatus::REVOKED;
        return res;
    }

    // 3. Step 3 Check: Cryptographic Anchor Validation
    if (!log_.verify_anchor(p.log_root_hash)) {
        res.status = VerifyStatus::LOG_MISMATCH;
        return res;
    }

    // 4. Step 4 Check: Quorum Threshold Validation
    if (!p.proof.is_complete()) {
        res.status = VerifyStatus::INSUFFICIENT_QUORUM;
        return res;
    }

    // 5. Multi-Party Signature Verification (Ed25519)
    std::string hash = p.content_hash();
    for (size_t i = 0; i < p.proof.signatures.size(); ++i) {
        auto pub_key = vault_.retrieve_public_key(p.proof.signer_ids[i]);
        
        // Note: content_hash returns Hex; signatures are typically Base64
        if (!ed25519_verify(pub_key, hex_decode(hash), base64_decode(p.proof.signatures[i]))) {
            res.status = VerifyStatus::INVALID_SIGNATURE;
            return res;
        }
    }

    res.status = VerifyStatus::OK;
    res.confidence = 1.0f;
    return res;
}

} // namespace uml001