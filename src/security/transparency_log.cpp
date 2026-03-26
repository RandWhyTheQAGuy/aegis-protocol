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
/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "uml001/security/transparency_log.h"
#include "uml001/crypto/crypto_utils.h"
#include <mutex>

namespace uml001 {

TransparencyLog::TransparencyLog(std::shared_ptr<IClock> clock, TransparencyMode mode)
    : clock_(clock), mode_(mode), current_state_(LogState::IDLE), root_(nullptr) {}

bool TransparencyLog::append(TransparencyEntry::Type type,
                             const std::string& event_type_str,
                             const std::string& payload_hash,
                             const std::string& signer_id,
                             const std::string& metadata,
                             uint64_t custom_timestamp) {
    std::lock_guard<std::mutex> guard(log_mutex_);
    current_state_ = LogState::APPENDING;

    TransparencyEntry entry;
    entry.type = type;
    entry.event_type = event_type_str;
    entry.payload_hash = payload_hash;
    entry.signer_id = signer_id;
    entry.metadata = metadata;
    entry.timestamp = (custom_timestamp > 0) ? custom_timestamp : clock_->now_unix();

    entry.entry_id = sha256_hex(payload_hash + "|" + std::to_string(entry.timestamp));
    entries_.push_back(entry);

    auto node = std::make_shared<MerkleNode>();
    node->hash = sha256_hex(entry.serialize_for_hash());
    leaves_.push_back(node);

    if (mode_ == TransparencyMode::IMMEDIATE) { rebuild_tree(); }

    current_state_ = LogState::IDLE;
    return true;
}

/** Returns the history of all entries in the transparency log.
 * @return A vector containing all transparency entries.
 */
std::vector<TransparencyEntry> TransparencyLog::history() const {
    std::lock_guard<std::mutex> guard(log_mutex_);
    return entries_;
}

/** Verifies the integrity of the transparency chain.
 * @return true if the chain is valid, false otherwise.
 */
bool TransparencyLog::verify_chain() const {
    std::lock_guard<std::mutex> guard(log_mutex_);

    if (leaves_.empty()) return true;

    auto recomputed = compute_recursive(leaves_);

    if (!recomputed || !root_) return false;

    return recomputed->hash == root_->hash;
}

/** Rebuilds the Merkle tree from the current leaves.
 * @param leaves The list of leaf nodes to use for rebuilding.
 */
void TransparencyLog::rebuild_tree() {
    // IMPORTANT: assumes caller already holds lock
    if (leaves_.empty()) return;

    root_ = compute_recursive(leaves_);
}

/** Computes the Merkle tree recursively.
 * @param level The list of nodes at the current level.
 * @return The root node of the computed tree.
 */
std::shared_ptr<MerkleNode> TransparencyLog::compute_recursive(
    const std::vector<std::shared_ptr<MerkleNode>>& level) const {

    if (level.empty()) return nullptr;
    if (level.size() == 1) return level[0];

    std::vector<std::shared_ptr<MerkleNode>> next_level;
    next_level.reserve((level.size() + 1) / 2);

    for (size_t i = 0; i < level.size(); i += 2) {
        auto parent = std::make_shared<MerkleNode>();
        parent->left = level[i];

        if (i + 1 < level.size()) {
            parent->right = level[i + 1];
            parent->hash = sha256_hex(level[i]->hash + level[i + 1]->hash);
        } else {
            // RFC6962-style duplication
            parent->hash = sha256_hex(level[i]->hash + level[i]->hash);
        }

        next_level.push_back(parent);
    }

    return compute_recursive(next_level);
}

std::string TransparencyLog::get_root_hash() const {
    std::lock_guard<std::mutex> guard(log_mutex_);
    return root_ ? root_->hash : "";
}

} // namespace uml001