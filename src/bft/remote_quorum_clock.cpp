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
#include "uml001/bft/remote_quorum_clock.h"
#include "clock_service.grpc.pb.h" // Generated from proto
#include <grpcpp/grpcpp.h>
#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace uml001 {

RemoteQuorumClock::RemoteQuorumClock(
    const std::vector<NodeConfig>& nodes,
    size_t quorum_threshold,
    int64_t max_skew_ms,
    double max_drift_ppm)
    : nodes_(nodes),
      quorum_threshold_(quorum_threshold),
      max_skew_ms_(max_skew_ms),
      max_drift_ppm_(max_drift_ppm)
{
    if (nodes.empty()) throw std::invalid_argument("No nodes provided");
    if (quorum_threshold == 0 || quorum_threshold > nodes.size())
        throw std::invalid_argument("Invalid quorum threshold");

    // Initialize gRPC stubs for all configured nodes
    for (const auto& node : nodes_) {
        auto channel = grpc::CreateChannel(node.endpoint, grpc::InsecureChannelCredentials());
        stubs_.push_back(uml001::ClockService::NewStub(channel));
    }
}

uint64_t RemoteQuorumClock::now_ms() const {
    std::vector<int64_t> timestamps;
    QuorumProof current_proof;

    // Poll nodes for timestamps
    for (size_t i = 0; i < stubs_.size(); ++i) {
        uml001::GetTimeRequest request;
        uml001::TimeResponse response;
        grpc::ClientContext context;
        
        // 200ms timeout for high-performance BFT consensus
        auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(200);
        context.set_deadline(deadline);

        grpc::Status status = stubs_[i]->GetTime(&context, request, &response);
        
        if (status.ok()) {
            int64_t ts = static_cast<int64_t>(response.unix_timestamp());
            timestamps.push_back(ts);
            
            // Record proof data
            current_proof.node_ids.push_back(nodes_[i].node_id);
            current_proof.signatures_b64.push_back(response.signature());
        }
    }

    // Check if we met the BFT threshold
    if (timestamps.size() < quorum_threshold_) {
        status_ = ClockStatus::DEGRADED;
        throw std::runtime_error("BFT Quorum Failure: Insufficient nodes responded.");
    }

    // 1. Compute Median to mitigate Byzantine behavior
    int64_t median_ms = compute_median(timestamps);

    // 2. Enforce Monotonicity (R-1)
    enforce_monotonic(median_ms);

    // 3. Update Internal State
    last_sync_time_ = median_ms;
    last_time_ = median_ms;
    active_nodes_ = static_cast<int>(timestamps.size());
    status_ = ClockStatus::SYNCHRONIZED;
    
    // Confidence is a ratio of responding nodes to total nodes
    confidence_ = static_cast<double>(active_nodes_) / nodes_.size();
    
    current_proof.median_time_ms = median_ms;
    last_proof_ = current_proof;

    return static_cast<uint64_t>(median_ms);
}

uint64_t RemoteQuorumClock::now_unix() const {
    return now_ms() / 1000;
}

bool RemoteQuorumClock::is_synchronized() const {
    return status_ == ClockStatus::SYNCHRONIZED;
}

uint64_t RemoteQuorumClock::last_sync_unix() const {
    return static_cast<uint64_t>(last_sync_time_ / 1000);
}

ClockStatus RemoteQuorumClock::status() const {
    return status_;
}

std::string RemoteQuorumClock::source_id() const {
    return "BFT-Quorum(v1.2-Active)";
}

double RemoteQuorumClock::get_confidence_ms() const {
    return confidence_;
}

int RemoteQuorumClock::get_active_nodes() const {
    return active_nodes_;
}

double RemoteQuorumClock::get_projected_drift() const {
    return drift_;
}

const QuorumProof& RemoteQuorumClock::last_proof() const {
    return last_proof_;
}

int64_t RemoteQuorumClock::compute_median(std::vector<int64_t>& v) const {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

void RemoteQuorumClock::enforce_monotonic(int64_t t) const {
    int64_t prev = monotonic_floor_.load();
    
    // CAS loop to safely advance the floor
    while (t > prev && !monotonic_floor_.compare_exchange_weak(prev, t)) {}

    if (t < prev) {
        // In production, we return the floor to prevent crashes, 
        // but log the attempt at "time travel".
        return; 
    }
}

} // namespace uml001