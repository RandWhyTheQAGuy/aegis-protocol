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

#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <optional>
#include "uml001/security/zk_proofs.h"  // Provides ZkProofType and ZkProofFactory

namespace uml001 {

enum class PolicyAction {
    ALLOW = 0,
    DENY,
    FLAG,
    REQUIRE_MFA
};

inline std::string action_str(PolicyAction a) {
    switch (a) {
        case PolicyAction::ALLOW:        return "ALLOW";
        case PolicyAction::DENY:         return "DENY";
        case PolicyAction::FLAG:         return "FLAG";
        case PolicyAction::REQUIRE_MFA:  return "REQUIRE_MFA";
        default:                         return "UNKNOWN";
    }
}

struct PolicyDecision {
    PolicyAction action = PolicyAction::DENY;
    std::string reason;
    std::string policy_id;

    // [E-8] Risk Multiplier: allows specific rules to "warp" the session faster
    float risk_weight = 1.0f;

    std::string payload_hash;
    std::string matched_rule_id;

    // ZK proof for confidential evaluation
    std::optional<std::vector<uint8_t>> zk_proof;
    security::ZkProofType proof_type = security::ZkProofType::RANGE_PROOF;
};

struct Constraint {
    std::string resource_id;
    std::string action;
    bool allowed = false;
};

struct Policy {
    std::string policy_id;
    std::string version;
    std::map<std::string, std::string> metadata;
    std::vector<Constraint> constraints;

    std::string compute_hash() const;
};

} // namespace uml001