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
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>

// gRPC and Protobuf dependencies
#include <grpcpp/grpcpp.h>
#include "clock_service.grpc.pb.h"

#include "uml001/core/clock.h"   // Matches your IClock base class
#include "uml001/crypto/crypto_utils.h"

namespace uml001 {

/**
 * @brief Represents a cryptographic proof of the time reached by the quorum.
 */
struct QuorumProof {
    std::vector<std::string> node_ids;
    std::vector<std::string> signatures_b64;
    int64_t median_time_ms = 0;
};

/**
 * @brief Hardened BFT Clock that aggregates time from multiple remote nodes.
 */
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

    // ------------------------------------------------------------------------
    // Core requirements for IClock interface (All strict const signatures)
    // ------------------------------------------------------------------------
    uint64_t now_unix() const override;
    uint64_t now_ms() const override;
    bool is_synchronized() const override;
    uint64_t last_sync_unix() const override;
    ClockStatus status() const override;
    std::string source_id() const override;

    // Metric accessors
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

    // Thread-safe floor to prevent time rollback
    std::atomic<int64_t> monotonic_floor_{0};

    // Cached metrics from the last successful sync
    int64_t last_time_{0};
    double confidence_{0.0};
    int active_nodes_{0};
    double drift_{0.0};
    QuorumProof last_proof_;

    // Private mutative helper to execute the BFT query 
    int64_t perform_sync();

    // Private helper methods for the BFT algorithm
    bool query_node(NodeClient& client, const std::string& request_id, quorumtime::TimeResponse& out);
    bool validate_response(const NodeClient& client, const quorumtime::TimeResponse& response, const std::string& request_id);
    std::string canonical_payload(const quorumtime::TimeResponse& r);
    int64_t compute_median(std::vector<int64_t>& values);
    void enforce_monotonic(int64_t new_time);
};

} // namespace uml001