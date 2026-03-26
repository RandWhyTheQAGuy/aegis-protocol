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
#include "uml001/bft/remote_quorum_clock.h"
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
}

uint64_t RemoteQuorumClock::now_ms() const {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

    enforce_monotonic(now_ms);

    last_time_ = now_ms;
    last_sync_time_ = now_ms;
    status_ = ClockStatus::SYNCHRONIZED;
    active_nodes_ = 1;
    confidence_ = 1.0;
    drift_ = 0.0;

    return static_cast<uint64_t>(now_ms);
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
    return "BFT-Quorum(STUB)";
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
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

void RemoteQuorumClock::enforce_monotonic(int64_t t) const {
    int64_t prev = monotonic_floor_.load();

    while (t > prev && !monotonic_floor_.compare_exchange_weak(prev, t)) {}

    if (t < prev) {
        throw std::runtime_error("Time rollback detected");
    }
}

} // namespace uml001