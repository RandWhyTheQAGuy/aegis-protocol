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
#include "uml001/core/policy.h"
#include "uml001/core/temporal_state.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/security/zk_proofs.h" // Include the ZK proof definitions
#include <sstream>

namespace uml001 {

/**
 * @brief Logic for write-access based on BFT Quorum/Clock state.
 */
bool allow_write(TemporalState state) {
    return state == TemporalState::SYNCHRONIZED ||
           state == TemporalState::CACHED;
}

/**
 * @brief Logic for read-access based on BFT Quorum/Clock state.
 */
bool allow_read(TemporalState state) {
    return state != TemporalState::UNTRUSTED;
}

/**
 * @brief Generates a deterministic hash of the policy for integrity checks.
 */
std::string Policy::compute_hash() const {
    std::stringstream ss;
    ss << policy_id << ":" << version << "|";

    // Include metadata
    for (const auto& [key, value] : metadata) {
        ss << key << ":" << value << ";";
    }

    // Include constraints
    for (const auto& constraint : constraints) {
        ss << constraint.resource_id << ":"
           << constraint.action << ":"
           << (constraint.allowed ? "1" : "0") << ";";
    }

    return sha256_hex(ss.str());
}

/**
 * @brief Evaluate a policy using a zero-knowledge proof.
 */
bool evaluate_policy_with_zk(const Policy& policy, 
                             const PolicyDecision& decision,
                             const std::string& context) {
    if (!decision.zk_proof.has_value()) {
        return false;  // ZK proof required
    }

    auto prover = security::ZkProofFactory::create_prover(decision.proof_type);
    return prover->verify(context, *decision.zk_proof);
}

} // namespace uml001