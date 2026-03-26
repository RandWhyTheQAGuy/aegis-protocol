/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
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
#include "uml001/security/transparency_log.h"
#include "uml001/security/revocation.h"
#include "uml001/core/clock.h"
#include "uml001/vault.h"
#include <iostream>
#include <cassert>
#include <vector>
#include <string>

using namespace uml001;

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

/**
 * @brief Simple Mock Clock to ensure deterministic timestamps during testing.
 */
class MockClock : public IClock {
public:
    uint64_t now_unix() const override { return 1711470000; } // Fixed point in time
    uint64_t now_ms() const override { return now_unix() * 1000; }
    bool is_synchronized() const override { return true; }
    uint64_t last_sync_unix() const override { return now_unix(); }
    ClockStatus status() const override { return ClockStatus::SYNCHRONIZED; }
    std::string source_id() const override { return "MOCK_BFT_CLOCK"; }
};

// -----------------------------------------------------------------------------
// Main Test Suite
// -----------------------------------------------------------------------------

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "   Aegis Protocol: Step 3 Anchor Verification Test  " << std::endl;
    std::cout << "====================================================" << std::endl;

    // 1. INFRASTRUCTURE SETUP
    auto clock = std::make_shared<MockClock>();
    TransparencyLog tlog(clock);
    RevocationList rlist(tlog);
    
    // Initialize the Vault for secure key storage
    VaultConfig vcfg;
    vcfg.vault_path = "test_audit.vault";
    ColdVault vault(vcfg);
    
    // Provision a test signing key (ID: 5050)
    // In production, this would be an Ed25519 or similar key.
    std::vector<uint8_t> test_key = {0x41, 0x65, 0x67, 0x69, 0x73, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74}; // "AegisSecret"
    vault.store("5050", test_key);

    // Initialize the Registry with the Security Triangle + Vault
    PassportRegistry registry(tlog, rlist, *clock, vault);

    // -------------------------------------------------------------------------
    // TEST 1: Legitimate Anchored Issuance
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 1] Issuing legitimate anchored passport..." << std::endl;
    
    Capabilities caps;
    caps.classifier_authority = true;
    caps.bft_consensus = true;
    
    Passport p_valid = registry.issue_model_passport(
        "aegis-core-v1", 
        "2.0.0", 
        caps, 
        "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", 
        5050
    );

    // Verify the anchor exists
    std::cout << "  > Passport Root Anchor: " << p_valid.log_root_hash << std::endl;
    assert(!p_valid.log_root_hash.empty());

    VerifyResult res_valid = registry.verify(p_valid);
    std::cout << "  > Verification Status: " << res_valid.status_str() << std::endl;
    assert(res_valid.ok());
    assert(res_valid.verified_key_id == 5050);

    // -------------------------------------------------------------------------
    // TEST 2: Detection of Missing Anchor (Floating Passport)
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 2] Testing detection of MISSING anchor (un-logged passport)..." << std::endl;
    
    Passport p_no_anchor = p_valid;
    p_no_anchor.log_root_hash = ""; // Simulate a passport that bypassed the log
    
    // We must re-sign the passport so it's "technically" valid cryptographically,
    // but the lack of an anchor should trigger LOG_MISMATCH.
    p_no_anchor.signature = hmac_sha256_hex("AegisSecret", p_no_anchor.content_hash());

    VerifyResult res_no_anchor = registry.verify(p_no_anchor);
    std::cout << "  > Verification Status: " << res_no_anchor.status_str() << " (Expected: LOG_MISMATCH)" << std::endl;
    assert(res_no_anchor.status == VerifyStatus::LOG_MISMATCH);

    // -------------------------------------------------------------------------
    // TEST 3: Detection of Tampered Content (Signature Break)
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 3] Testing detection of tampered capabilities..." << std::endl;
    
    Passport p_tampered = p_valid;
    p_tampered.capabilities.entropy_flush = true; // Unauthorized elevation of privilege

    VerifyResult res_tampered = registry.verify(p_tampered);
    std::cout << "  > Verification Status: " << res_tampered.status_str() << " (Expected: INVALID_SIGNATURE)" << std::endl;
    assert(res_tampered.status == VerifyStatus::INVALID_SIGNATURE);

    // -------------------------------------------------------------------------
    // TEST 4: Revocation Integration (Complete Lifecycle)
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 4] Testing integration with Revocation System..." << std::endl;
    
    const std::string model_to_revoke = "aegis-core-v1";

    // 1. Propose (This adds the intent to the Transparency Log)
    rlist.propose_revocation(model_to_revoke, "Compromised in test scenario");
    
    // 2. Approve (In a real BFT quorum, this would be multiple nodes)
    // Note: Assuming the proposal_id matches the model_id for this mock/v1.2
    rlist.approve_revocation(model_to_revoke); 

    // 3. Finalize (This moves the model into the 'revoked_models_' set)
    rlist.finalize_revocation(model_to_revoke);
    
    VerifyResult res_revoked = registry.verify(p_valid);
    std::cout << "  > Verification Status: " << res_revoked.status_str() << " (Expected: REVOKED)" << std::endl;
    
    assert(res_revoked.status == VerifyStatus::REVOKED);

    return 0;
}