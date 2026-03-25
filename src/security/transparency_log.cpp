/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/security/transparency_log.h"
#include "uml001/crypto/crypto_utils.h"
#include <algorithm>
#include <stdexcept>

namespace uml001 {

TransparencyLog::TransparencyLog(std::shared_ptr<IClock> clock, TransparencyMode mode)
    : clock_(clock), mode_(mode), current_state_(LogState::IDLE), root_(nullptr) {
    if (!clock_) {
        throw std::invalid_argument("TransparencyLog requires a valid IClock instance.");
    }
}

bool TransparencyLog::append(TransparencyEntry::Type type, 
                            const std::string& event_type_str,
                            const std::string& payload_hash, 
                            const std::string& signer_id) {
    current_state_ = LogState::APPENDING;
    
    TransparencyEntry entry;
    entry.type = type;
    entry.event_type = event_type_str;
    entry.payload_hash = payload_hash;
    entry.signer_id = signer_id;
    entry.timestamp = clock_->now_unix(); 

    // Generate unique ID for this log entry
    // Generate unique ID for this log entry
    entry.entry_id = sha256_hex(payload_hash + "|" + std::to_string(entry.timestamp));

    entries_.push_back(entry);

    entries_.push_back(entry);

    auto node = std::make_shared<MerkleNode>();
    node->hash = sha256_hex(entry.serialize_for_hash());
    leaves_.push_back(node);

    if (mode_ == TransparencyMode::IMMEDIATE) {
        rebuild_tree();
    }

    current_state_ = LogState::IDLE;
    return true;
}

std::vector<TransparencyEntry> TransparencyLog::history() const {
    return entries_;
}

bool TransparencyLog::verify_chain() const {
    if (leaves_.empty()) {
        return true;
    }
    
    // Recompute the root hash
    auto recomputed = compute_recursive(leaves_);
    if (!recomputed || !root_) {
        return false;
    }
    
    // Verify hashes match
    return recomputed->hash == root_->hash;
}

std::vector<TransparencyEntry> TransparencyLog::history() const {
    return entries_;
}

bool TransparencyLog::verify_chain() const {
    if (leaves_.empty()) {
        return true;
    }
    
    // Recompute the root hash
    auto recomputed = compute_recursive(leaves_);
    if (!recomputed || !root_) {
        return false;
    }
    
    // Verify hashes match
    return recomputed->hash == root_->hash;
}

void TransparencyLog::rebuild_tree() {
    if (leaves_.empty()) return;
    root_ = compute_recursive(leaves_);
}

std::shared_ptr<MerkleNode> TransparencyLog::compute_recursive(
    const std::vector<std::shared_ptr<MerkleNode>>& level) const {
    const std::vector<std::shared_ptr<MerkleNode>>& level) const {
    
    if (level.empty()) return nullptr;
    if (level.size() == 1) return level[0];

    std::vector<std::shared_ptr<MerkleNode>> next_level;
    for (size_t i = 0; i < level.size(); i += 2) {
        auto parent = std::make_shared<MerkleNode>();
        if (i + 1 < level.size()) {
            parent->left = level[i];
            parent->right = level[i+1];
            parent->hash = sha256_hex(level[i]->hash + level[i+1]->hash);
        } else {
            // Odd number of nodes: promote the last node hash upward
            parent->left = level[i];
            parent->hash = level[i]->hash; 
        }
        next_level.push_back(parent);
    }
    return compute_recursive(next_level);
}

std::string TransparencyLog::get_root_hash() const {
    return root_ ? root_->hash : "";
}

} // namespace uml001