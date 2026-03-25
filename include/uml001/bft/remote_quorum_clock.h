#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <atomic>

#include <grpcpp/grpcpp.h>
#include "clock_service.grpc.pb.h"

#include "uml001/core/clock.h"

namespace uml001 {

struct QuorumProof {
    std::vector<std::string> node_ids;
    std::vector<std::string> signatures_b64;
    int64_t median_time_ms = 0;
};

class RemoteQuorumClock : public IClock {
public:
    struct NodeConfig {
        std::string endpoint;
        std::string node_id;
        std::string pubkey_base64;
    };

    RemoteQuorumClock(
        const std::vector<NodeConfig>& nodes,
        size_t quorum_threshold,
        int64_t max_skew_ms = 5000,
        double max_drift_ppm = 100.0
    );

    // IClock interface implementation
    uint64_t now_unix() const override;
    uint64_t now_ms() const override;
    bool is_synchronized() const override;
    uint64_t last_sync_unix() const override;
    ClockStatus status() const override;
    std::string source_id() const override;

    // Additional accessors for BFT metrics
    double get_confidence_ms() const;
    int get_active_nodes() const;
    double get_projected_drift() const;

    const QuorumProof& last_proof() const;

private:
    struct NodeClient {
        std::string endpoint;
        std::string node_id;
        std::vector<uint8_t> pubkey;
        std::unique_ptr<quorumtime::ClockService::Stub> stub;
    };

    std::vector<NodeClient> clients_;
    size_t quorum_threshold_;
    int64_t max_skew_ms_;
    double max_drift_ppm_;

    mutable std::atomic<int64_t> monotonic_floor_{0};
    
    // Clock state tracking (mutable to allow updates in const now_unix() method)
    mutable int64_t last_sync_time_ = 0;
    mutable ClockStatus current_status_ = ClockStatus::UNKNOWN;
    mutable int64_t last_time_ = 0;
    mutable double confidence_ = 0.0;
    mutable double drift_ = 0.0;
    mutable int active_nodes_ = 0;

    mutable QuorumProof last_proof_;

private:
    bool query_node(const NodeClient& client,
                    const std::string& request_id,
                    quorumtime::TimeResponse& out) const;

    bool validate_response(
        const NodeClient& client,
        const quorumtime::TimeResponse& r,
        const std::string& request_id
    ) const;

    std::string canonical_payload(const quorumtime::TimeResponse& r) const;

    int64_t compute_median(std::vector<int64_t>& values) const;

    void enforce_monotonic(int64_t new_time) const;
};

} // namespace uml001