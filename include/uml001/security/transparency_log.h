#pragma once

#include "uml001/core/iclock.h"
#include "uml001/bft/remote_quorum_clock.h"
#include "uml001/crypto/crypto_utils.h"

#include <string>
#include <vector>
#include <memory>

namespace uml001 {

enum class LogState { IDLE, APPENDING, SYNCHRONIZING, SEALED, FAULT };
enum class TransparencyMode { IMMEDIATE, PERIODIC_SEALING };

struct TransparencyEntry {
    std::string entry_id;
    uint64_t timestamp = 0;

    std::string payload_hash;
    std::string signer_id;

    QuorumProof quorum; // 🔐 NEW

    std::string serialize_for_hash() const {
        return entry_id + "|" + std::to_string(timestamp) + "|" +
               payload_hash + "|" + signer_id;
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

    bool append(const std::string& payload_hash,
                const std::string& signer_id);

    std::string get_root_hash() const;

private:
    std::shared_ptr<IClock> clock_;
    std::shared_ptr<RemoteQuorumClock> quorum_clock_; // 🔐

    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;

    void rebuild_tree();
};

} // namespace uml001