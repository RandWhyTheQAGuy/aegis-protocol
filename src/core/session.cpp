/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0
 */

#include "uml001/core/session.h"
#include "uml001/crypto/simple_hash_provider.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace uml001 {

// ============================================================
// Constructor
// ============================================================

Session::Session(std::string session_id,
                 std::string peer_model_id,
                 float       warp_threshold,
                 FlushCallback on_flush)
    : session_id_(std::move(session_id))
    , peer_model_id_(std::move(peer_model_id))
    , warp_threshold_(warp_threshold)
    , on_flush_(std::move(on_flush))
    , state_(SessionState::INIT)
    , warp_score_(0.0f) {}

// ============================================================
// Lifecycle
// ============================================================

void Session::activate() {
    require_state(SessionState::INIT, "activate");
    transition(SessionState::ACTIVE, "handshake_complete");
}

void Session::close() {
    transition(SessionState::CLOSED, "session_terminated");
}

bool Session::is_active() const {
    return (state_ == SessionState::ACTIVE ||
            state_ == SessionState::SUSPECT);
}

// ============================================================
// Core Decision Processing (SECURITY CRITICAL)
// ============================================================

bool Session::process_decision(const PolicyDecision& decision, uint64_t now_ms) {
    // Fail-closed for terminal states
    if (state_ == SessionState::QUARANTINE ||
        state_ == SessionState::FLUSHING   ||
        state_ == SessionState::CLOSED) {
        return false;
    }

    // --------------------------------------------------------
    // 1. Warp Score Calculation (preserve weighted model)
    // --------------------------------------------------------
    float base_weight = 0.0f;

    switch (decision.action) {
        case PolicyAction::DENY:        base_weight = WARP_WEIGHT_DENY; break;
        case PolicyAction::FLAG:        base_weight = WARP_WEIGHT_FLAG; break;
        case PolicyAction::REQUIRE_MFA: base_weight = WARP_WEIGHT_MFA;  break;
        case PolicyAction::ALLOW:       base_weight = WARP_WEIGHT_ALLOW; break;
        default:                        base_weight = 0.0f; break;
    }

    float delta = base_weight * decision.risk_weight;
    warp_score_ = std::max(0.0f, warp_score_ + delta);

    // --------------------------------------------------------
    // 2. Entropy Buffer (anti-probing)
    // --------------------------------------------------------
    payload_buffer_.push_back(decision.payload_hash);

    if (payload_buffer_.size() > MAX_BUFFER) {
        payload_buffer_.pop_front();
    }

    // --------------------------------------------------------
    // 3. State Transitions
    // --------------------------------------------------------

    if (warp_score_ >= (warp_threshold_ * 3.0f)) {
        transition(SessionState::QUARANTINE, "warp_critical_threshold");
        initiate_flush(now_ms);
        return false;
    }

    if (warp_score_ >= warp_threshold_ &&
        state_ == SessionState::ACTIVE) {
        transition(SessionState::SUSPECT, "warp_elevated_risk");
    }

    if (warp_score_ < (warp_threshold_ * 0.5f) &&
        state_ == SessionState::SUSPECT) {
        transition(SessionState::ACTIVE, "warp_stabilized");
    }

    // --------------------------------------------------------
    // 4. Audit Logging (FIXED: consistent structure)
    // --------------------------------------------------------
    log_event("POLICY_DECISION",
              action_str(decision.action) +
              " weight=" + std::to_string(delta),
              now_ms,
              decision.payload_hash);

    // --------------------------------------------------------
    // 5. Flush Trigger (security critical)
    // --------------------------------------------------------
    if (decision.action == PolicyAction::DENY ||
        payload_buffer_.size() >= MAX_BUFFER) {
        initiate_flush(now_ms);
    }

    return (state_ != SessionState::QUARANTINE &&
            decision.action != PolicyAction::DENY);
}

// ============================================================
// Flush Logic (SECURITY CRITICAL)
// ============================================================

void Session::initiate_flush(uint64_t now_ms) {
    if (state_ != SessionState::QUARANTINE &&
        state_ != SessionState::CLOSED) {
        transition(SessionState::FLUSHING, "entropy_flush_start");
    }

    // Deterministic incident ID
    std::string salt = session_id_ + std::to_string(now_ms);
    std::string incident_id =
        crypto::SimpleHashProvider::instance().sha256(salt);

    std::vector<std::string> tainted(
        payload_buffer_.begin(),
        payload_buffer_.end()
    );

    payload_buffer_.clear();

    if (on_flush_) {
        on_flush_(session_id_, incident_id, tainted);
    }

    if (state_ == SessionState::FLUSHING) {
        transition(SessionState::RESYNC, "awaiting_resync");
    }
}

void Session::complete_flush() {
    require_state(SessionState::FLUSHING, "complete_flush");
    transition(SessionState::RESYNC, "flush_complete");
}

void Session::reactivate() {
    require_state(SessionState::RESYNC, "reactivate");

    warp_score_ = 0.0f;
    payload_buffer_.clear();

    transition(SessionState::ACTIVE, "resync_successful");
}

// ============================================================
// State Management
// ============================================================

void Session::transition(SessionState next, const std::string& reason) {
    if (state_ == next) return;

    std::string detail =
        state_str(state_) + " -> " +
        state_str(next) +
        " reason=" + reason +
        " score=" + std::to_string(warp_score_);

    state_ = next;

    log_event("STATE_TRANSITION", detail, 0);
}

void Session::require_state(SessionState expected,
                            const std::string& op) const {
    if (state_ != expected) {
        throw std::runtime_error(
            "Session error: " + op +
            " invalid in " + state_str(state_));
    }
}

// ============================================================
// State String Representation
// ============================================================

std::string Session::state_str(SessionState s) {
    switch (s) {
        case SessionState::INIT:       return "INIT";
        case SessionState::ACTIVE:     return "ACTIVE";
        case SessionState::SUSPECT:    return "SUSPECT";
        case SessionState::QUARANTINE: return "QUARANTINE";
        case SessionState::FLUSHING:   return "FLUSHING";
        case SessionState::RESYNC:     return "RESYNC";
        case SessionState::CLOSED:     return "CLOSED";
        default:                       return "UNKNOWN";
    }
}

// ============================================================
// Logging (FIXED + CONSISTENT)
// ============================================================

void Session::log_event(const std::string& type,
                        const std::string& detail,
                        uint64_t ts,
                        const std::string& payload_hash) {
    event_log_.push_back({
        ts,
        type,
        payload_hash,
        detail
    });
}

} // namespace uml001