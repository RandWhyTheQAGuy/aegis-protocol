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

#include <string>
#include <vector>
#include <deque>
#include <functional>
#include <cstdint>
#include "uml001/core/policy.h"

namespace uml001 {

// --------------------
// Session State Enum
// --------------------
enum class SessionState {
    INIT,
    ACTIVE,
    SUSPECT,      // Warp Score > Threshold 1
    QUARANTINE,   // Warp Score > Threshold 2 (Fail-Closed)
    FLUSHING,     // Entropy Reset in progress
    RESYNC,       // Recovering from Clock Drift
    CLOSED
};

// --------------------
// Warp Weights & Decay
// --------------------
static constexpr float WARP_WEIGHT_ALLOW   = -0.1f; // Successful clean ops reduce score
static constexpr float WARP_WEIGHT_FLAG    =  0.5f;
static constexpr float WARP_WEIGHT_DENY    =  1.0f;
static constexpr float WARP_WEIGHT_MFA     =  0.2f;

static constexpr float WARP_SCORE_MAX      = 100.0f;   // Prevent unbounded growth
static constexpr float WARP_DECAY_RATE     = 0.01f;    // 1% decay per decision
static constexpr uint64_t WARP_DECAY_TIME_MS = 60000;  // Decay every minute

// --------------------
// Session Event
// --------------------
struct SessionEvent {
    uint64_t timestamp;
    std::string type;
    std::string payload_hash;
    std::string details;
};

// --------------------
// Session Class
// --------------------
class Session {
public:
    using FlushCallback = std::function<void(const std::string&, const std::string&, const std::vector<std::string>&)>;

    Session(std::string session_id,
            std::string peer_model_id,
            float warp_threshold,
            FlushCallback on_flush);

    void activate();

    /**
     * @brief Processes a policy decision and updates the Warp Score.
     * If score exceeds threshold, transitions to SUSPECT or QUARANTINE.
     */
    bool process_decision(const PolicyDecision& decision, uint64_t now_ms);

    void initiate_flush(uint64_t now_ms);
    void complete_flush();
    void reactivate();
    void close();

    // Accessors
    bool is_active() const { return state_ == SessionState::ACTIVE || state_ == SessionState::SUSPECT; }
    SessionState state() const { return state_; }
    float warp_score() const { return warp_score_; }
    static std::string state_str(SessionState s);

private:
    void transition(SessionState next, const std::string& reason);
    void log_event(const std::string& type, const std::string& detail, uint64_t ts);
    void require_state(SessionState expected, const std::string& op) const;

    std::string session_id_;
    std::string peer_model_id_;
    float warp_threshold_;               // Base threshold for SUSPECT
    FlushCallback on_flush_;

    SessionState state_;
    float warp_score_;
    uint64_t last_decision_time_ms_;     // For time-based decay

    std::deque<std::string> payload_buffer_;
    std::vector<SessionEvent> event_log_;
    static constexpr size_t MAX_BUFFER = 100;
};

} // namespace uml001