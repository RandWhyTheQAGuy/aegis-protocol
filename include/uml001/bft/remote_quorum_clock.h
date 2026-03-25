/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include "uml001/core/clock.h"
#include "uml001/core/clock.h"
#include <string>
#include <memory>

namespace uml001 {

/**
 * @brief Implementation of IClock that fetches time from the BFT Quorum.
 */
/**
 * @brief Implementation of IClock that fetches time from the BFT Quorum.
 */
class RemoteQuorumClock : public IClock {
public:
    RemoteQuorumClock(const std::string& quorum_address);
    virtual ~RemoteQuorumClock() = default;

    // Interface Implementation (Fixes the 'abstract class' and 'hidden virtual' errors)
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
    RemoteQuorumClock(const std::string& quorum_address);
    virtual ~RemoteQuorumClock() = default;

    // Interface Implementation (Fixes the 'abstract class' and 'hidden virtual' errors)
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
                    quorumtime::TimeResponse& out) const;

    bool validate_response(
        const NodeClient& client,
        const quorumtime::TimeResponse& r,
        const std::string& request_id
    ) const;
    ) const;

    std::string canonical_payload(const quorumtime::TimeResponse& r) const;
    std::string canonical_payload(const quorumtime::TimeResponse& r) const;

    int64_t compute_median(std::vector<int64_t>& values) const;
    int64_t compute_median(std::vector<int64_t>& values) const;

    void enforce_monotonic(int64_t new_time) const;
    void enforce_monotonic(int64_t new_time) const;
};

} // namespace uml001