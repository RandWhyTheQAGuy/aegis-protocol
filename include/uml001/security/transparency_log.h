/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include "uml001/core/clock.h"

#include "uml001/crypto/crypto_utils.h"
#include <string>
#include <vector>
#include <memory>

namespace uml001 {

/**
 * @brief Represents a BFT Quorum validation for a specific log entry.
 */
struct QuorumProof {
    std::vector<std::string> signatures;
    uint32_t quorum_size = 0;
    std::string root_signature;
};

enum class LogState { IDLE, APPENDING, SYNCHRONIZING, SEALED, FAULT };
enum class TransparencyMode { IMMEDIATE, PERIODIC_SEALING };

struct TransparencyEntry {
    enum class Type {
        GENERIC,
        POLICY_UPDATE,
        REVOCATION_PROPOSED,
        REVOCATION_APPROVED,
        REVOCATION_FINALIZED
    };

    Type type = Type::ENTRY_UNKNOWN;
    std::string event_type;      ///< Human-readable event description
    enum class Type {
        GENERIC,
        POLICY_UPDATE,
        REVOCATION_PROPOSED,
        REVOCATION_APPROVED,
        REVOCATION_FINALIZED
    };

    Type type = Type::GENERIC;
    std::string event_type; // e.g., "CERT_REVOKE"
    std::string entry_id;
    uint64_t timestamp = 0;
    std::string payload_hash;
    std::string signer_id;
    QuorumProof quorum;

    std::string serialize_for_hash() const {
        return entry_id + "|" + std::to_string(timestamp) + "|" +
               payload_hash + "|" + signer_id + "|" + event_type;
        return std::to_string(static_cast<int>(type)) + "|" +
               event_type + "|" +
               entry_id + "|" + 
               std::to_string(timestamp) + "|" +
               payload_hash + "|" + 
               signer_id;
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
    /**
     * @brief Appends a new security event to the Merkle Tree.
     */
    bool append(TransparencyEntry::Type type, 
                const std::string& event_type_str,
                const std::string& payload_hash, 
                const std::string& signer_id);

    /**
     * @brief Retrieves the full history of log entries.
     * [E-7] Auditability: Complete chain for external verification
     */
    std::vector<TransparencyEntry> history() const;

    /**
     * @brief Verifies the integrity of the Merkle chain.
     * [E-7] Chain Verification: Ensures no tampering by recomputing root
     */
    bool verify_chain() const;

    std::string get_root_hash() const;
    LogState state() const { return current_state_; }

private:
    std::shared_ptr<MerkleNode> compute_recursive(
        const std::vector<std::shared_ptr<MerkleNode>>& level);
    
    void rebuild_tree();

    std::shared_ptr<IClock> clock_;
    TransparencyMode mode_;
    
    TransparencyMode mode_;
    LogState current_state_;

    std::vector<TransparencyEntry> entries_;
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;

    std::shared_ptr<IClock> clock_;
    TransparencyMode mode_;
    LogState current_state_;

    std::vector<TransparencyEntry> entries_;
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;
};

} // namespace uml001