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

#include "uml001/core/clock.h"
#include "uml001/core/passport.h" // For QuorumProof
#include <string>
#include <vector>
#include <memory>
#include <mutex>

namespace uml001 {

enum class LogState { IDLE, APPENDING, SYNCHRONIZING, SEALED, FAULT };
enum class TransparencyMode { IMMEDIATE, PERIODIC_SEALING };

struct TransparencyEntry {
    enum class Type {
        GENERIC, POLICY_UPDATE, REVOCATION_PROPOSED, 
        REVOCATION_APPROVED, REVOCATION_FINALIZED, PASSPORT_ISSUED
    };

    Type type = Type::GENERIC;
    std::string event_type;
    std::string entry_id;
    uint64_t timestamp = 0;
    std::string payload_hash;
    std::string signer_id;
    std::string metadata;
    QuorumProof quorum;

    std::string serialize_for_hash() const {
        return entry_id + "|" + std::to_string(timestamp) + "|" +
               payload_hash + "|" + signer_id + "|" + event_type + "|" + metadata;
    }
};

struct MerkleNode {
    std::string hash;
    std::shared_ptr<MerkleNode> left;
    std::shared_ptr<MerkleNode> right;
};

class TransparencyLog {
public:
    explicit TransparencyLog(std::shared_ptr<IClock> clock,
                             TransparencyMode mode = TransparencyMode::IMMEDIATE);

    bool append(TransparencyEntry::Type type,
                const std::string& event_type_str,
                const std::string& payload_hash,
                const std::string& signer_id,
                const std::string& metadata = "",
                uint64_t custom_timestamp = 0);

    bool verify_anchor(const std::string& root_hash) const;
    std::vector<TransparencyEntry> history() const;
    bool verify_chain() const;
    std::string get_root_hash() const;
    LogState state() const { return current_state_; }

private:
    std::shared_ptr<MerkleNode> compute_recursive(const std::vector<std::shared_ptr<MerkleNode>>& level) const;
    void rebuild_tree();

    std::shared_ptr<IClock> clock_;
    TransparencyMode mode_;
    LogState current_state_;
    std::vector<TransparencyEntry> entries_;
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;
    mutable std::mutex log_mutex_;
};

} // namespace uml001