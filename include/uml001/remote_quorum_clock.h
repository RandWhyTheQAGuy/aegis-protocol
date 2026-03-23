#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <cstdint>

#include <grpcpp/grpcpp.h>
#include "clock_service.grpc.pb.h"

#include "uml001/core/iclock.h"
#include "uml001/crypto_utils.h"

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

    int64_t now_unix() override;

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

    std::atomic<int64_t> monotonic_floor_{0};

    int64_t last_time_{0};
    double confidence_{0.0};
    int active_nodes_{0};
    double drift_{0.0};

    QuorumProof last_proof_;

private:
    bool query_node(NodeClient& client,
                    const std::string& request_id,
                    quorumtime::TimeResponse& out);

    bool validate_response(const NodeClient& client,
                           const quorumtime::TimeResponse& response,
                           const std::string& request_id);

    std::string canonical_payload(const quorumtime::TimeResponse& r);

    int64_t compute_median(std::vector<int64_t>& values);

    void enforce_monotonic(int64_t new_time);
};

} // namespace uml001