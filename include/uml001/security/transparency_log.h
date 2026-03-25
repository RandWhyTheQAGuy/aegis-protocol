#pragma once

#include "uml001/core/clock.h"
#include "uml001/crypto/crypto_utils.h"

#include <string>
#include <vector>
#include <memory>

namespace uml001 {

enum class LogState { IDLE, APPENDING, SYNCHRONIZING, SEALED, FAULT };
enum class TransparencyMode { IMMEDIATE, PERIODIC_SEALING };

struct TransparencyEntry {
    enum class Type {
        ENTRY_UNKNOWN,           ///< Unknown/uninitialized entry
        REVOCATION_PROPOSED,     ///< Key revocation proposed
        REVOCATION_APPROVED,     ///< Key revocation approved by quorum
        REVOCATION_FINALIZED,    ///< Key revocation finalized
        AUDIT_LOG_ENTRY,         ///< Audit log entry
        SECURITY_EVENT,          ///< Security-relevant event
        STATE_TRANSITION,        ///< State machine transition
        WARP_SCORE_UPDATE,       ///< Warp score threshold breach
        ENTROPY_FLUSH,           ///< Entropy flush operation
        PASSPORT_ISSUED          ///< Passport issuance event
    };

    Type type = Type::ENTRY_UNKNOWN;
    std::string event_type;      ///< Human-readable event description
    std::string entry_id;
    uint64_t timestamp = 0;
    std::string payload_hash;
    std::string signer_id;

    std::string serialize_for_hash() const {
        return entry_id + "|" + std::to_string(timestamp) + "|" +
               payload_hash + "|" + signer_id + "|" + event_type;
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
                const std::string& signer_id);

    std::string get_root_hash() const;

private:
    std::shared_ptr<IClock> clock_;
    LogState current_state_ = LogState::IDLE;
    TransparencyMode mode_;
    
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;

    void rebuild_tree();
    std::shared_ptr<MerkleNode> compute_recursive(
        const std::vector<std::shared_ptr<MerkleNode>>& level);
};

} // namespace uml001