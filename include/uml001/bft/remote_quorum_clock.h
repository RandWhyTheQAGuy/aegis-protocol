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

#include "uml001/core/clock.h"
#include <string>
#include <vector>
#include <memory>
#include <atomic>

namespace uml001 {

struct NodeConfig {
    std::string endpoint;
    std::string node_id;
    std::string pubkey_base64;
};

struct QuorumProof {
    std::vector<std::string> node_ids;
    std::vector<std::string> signatures_b64;
    int64_t median_time_ms = 0;
};

class RemoteQuorumClock : public IClock {
public:
    RemoteQuorumClock(const std::vector<NodeConfig>& nodes,
                      size_t quorum_threshold,
                      int64_t max_skew_ms,
                      double max_drift_ppm);

    ~RemoteQuorumClock() override = default;

    uint64_t now_unix() const override;
    uint64_t now_ms() const override;
    bool is_synchronized() const override;
    uint64_t last_sync_unix() const override;
    ClockStatus status() const override;
    std::string source_id() const override;

    double get_confidence_ms() const;
    int get_active_nodes() const;
    double get_projected_drift() const;

    const QuorumProof& last_proof() const;

private:
    std::vector<NodeConfig> nodes_;

    size_t quorum_threshold_;
    int64_t max_skew_ms_;
    double max_drift_ppm_;

    mutable std::atomic<int64_t> monotonic_floor_{0};

    mutable int64_t last_time_ = 0;
    mutable int64_t last_sync_time_ = 0;
    mutable ClockStatus status_ = ClockStatus::UNKNOWN;

    mutable double confidence_ = 0;
    mutable double drift_ = 0;
    mutable int active_nodes_ = 0;

    mutable QuorumProof last_proof_;

    int64_t compute_median(std::vector<int64_t>& values) const;
    void enforce_monotonic(int64_t t) const;
};

} // namespace uml001