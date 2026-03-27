/** Aegis Protocol (Semantic Passport System)
* =========================================
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 */
#include "uml001/core/registry.h" 
#include "uml001/security/transparency_log.h"
#include "uml001/security/revocation.h"
#include "uml001/core/clock.h"
#include "uml001/security/vault.h"
#include <iostream>
#include <cassert>
#include <vector>

using namespace uml001;

// Mock Clock for deterministic testing
class SwarmClock : public IClock {
public:
    uint64_t now_unix() const override { return 1711470000; }
    bool is_synchronized() const override { return true; }
};

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "   Aegis Protocol: V1.3 Swarm Resilience Test       " << std::endl;
    std::cout << "====================================================" << std::endl;

    // 1. SETUP INFRASTRUCTURE
    auto clock = std::make_shared<SwarmClock>();
    TransparencyLog tlog(clock);
    RevocationList rlist(tlog);
    
    VaultConfig vcfg;
    ColdVault vault(vcfg);
    
    // Provision 3 Signing Nodes (The Quorum)
    vault.store("5001", {0xAA, 0x11}); // Mock Key 1
    vault.store("5002", {0xBB, 0x22}); // Mock Key 2
    vault.store("5003", {0xCC, 0x33}); // Mock Key 3 (Simulated Offline later)

    PassportRegistry registry(tlog, rlist, *clock, vault);

    // -------------------------------------------------------------------------
    // TEST 1: 2-of-3 Quorum Issuance (Standard Ops)
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 1] Issuing 2-of-3 Quorum Passport..." << std::endl;
    
    vault.add_known_peer("drone-alpha"); // Add to Trust Boundary
    
    std::vector<uint32_t> signers = {5001, 5002}; 
    Passport p_quorum = registry.issue_model_passport(
        "drone-alpha", "1.0.0", Capabilities(), "policy-v1", signers, 2
    );

    assert(p_quorum.proof.signatures.size() == 2);
    assert(p_quorum.proof.is_complete());
    
    VerifyResult res1 = registry.verify(p_quorum);
    std::cout << "  > Quorum Verification: " << res1.status_str() << std::endl;
    assert(res1.ok());

    // -------------------------------------------------------------------------
    // TEST 2: Trust Boundary Violation (Unknown Node)
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 2] Testing Trust Boundary (Unknown Drone)..." << std::endl;
    
    Passport p_rogue = p_quorum;
    p_rogue.model_id = "drone-unknown"; // Not in vault.known_peers_

    VerifyResult res2 = registry.verify(p_rogue);
    std::cout << "  > Verification Status: " << res2.status_str() << " (Expected: INVALID_SIGNATURE/REJECTED)" << std::endl;
    assert(!res2.ok());

    // -------------------------------------------------------------------------
    // TEST 3: Attrition Handling (1 Node Offline)
    // -------------------------------------------------------------------------
    std::cout << "\n[TEST 3] Simulating 1/3 Node Attrition..." << std::endl;
    
    // We attempt to issue a passport requiring 2 signers, but one key is "missing"
    std::vector<uint32_t> surviving_signers = {5001}; // 5002 and 5003 are "offline"
    
    Passport p_failed = registry.issue_model_passport(
        "drone-alpha", "1.0.0", Capabilities(), "policy-v1", surviving_signers, 2
    );

    VerifyResult res3 = registry.verify(p_failed);
    std::cout << "  > Verification Status: " << res3.status_str() << " (Expected: INSUFFICIENT_QUORUM)" << std::endl;
    assert(res3.status == VerifyStatus::INSUFFICIENT_QUORUM);

    std::cout << "\n====================================================" << std::endl;
    std::cout << "   SUCCESS: V1.3 Resilience Validated               " << std::endl;
    std::cout << "====================================================" << std::endl;

    return 0;
}