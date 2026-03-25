#include "uml001/crypto/crypto_utils.h"
#include "uml001/security/transparency_log.h"
#include <algorithm>
#include <stdexcept>

namespace uml001 {

TransparencyLog::TransparencyLog(std::shared_ptr<IClock> clock, TransparencyMode mode)
    : clock_(clock), current_state_(LogState::IDLE), mode_(mode), root_(nullptr) {
    // Security check: Ensure the log is never created without a trusted clock
    if (!clock_) {
        throw std::invalid_argument("TransparencyLog requires a valid IClock instance for trusted timestamps.");
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
    
    // Pull the timestamp directly from our secure, internal clock
    entry.timestamp = clock_->now_unix(); 

    entry.entry_id = uml001::sha256_hex(payload_hash + "|" + std::to_string(entry.timestamp));

    auto node = std::make_shared<MerkleNode>();
    node->hash = uml001::sha256_hex(entry.serialize_for_hash());
    leaves_.push_back(node);

    if (mode_ == TransparencyMode::IMMEDIATE) {
        rebuild_tree();
    }

    current_state_ = LogState::IDLE;
    return true;
}

void TransparencyLog::rebuild_tree() {
    if (leaves_.empty()) return;
    root_ = compute_recursive(leaves_);
}

std::shared_ptr<MerkleNode> TransparencyLog::compute_recursive(
    const std::vector<std::shared_ptr<MerkleNode>>& level) {
    
    if (level.size() == 1) return level[0];

    std::vector<std::shared_ptr<MerkleNode>> next_level;
    for (size_t i = 0; i < level.size(); i += 2) {
        auto parent = std::make_shared<MerkleNode>();
        if (i + 1 < level.size()) {
            parent->left = level[i];
            parent->right = level[i+1];
            parent->hash = uml001::sha256_hex(level[i]->hash + level[i+1]->hash);
        } else {
            parent->left = level[i];
            parent->hash = level[i]->hash; // Odd leaf promotion
        }
        next_level.push_back(parent);
    }
    return compute_recursive(next_level);
}

std::string TransparencyLog::get_root_hash() const {
    return root_ ? root_->hash : "";
}

} // namespace uml001