/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/core/session.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/crypto/simple_hash_provider.h"
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <iostream>

namespace uml001 {

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

void Session::activate() {
    require_state(SessionState::INIT, "activate");
    transition(SessionState::ACTIVE, "handshake_complete");
}

bool Session::process_decision(const PolicyDecision& decision, uint64_t now_ms) {
    // Fail-closed logic for Terminal or Locked states
    if (state_ == SessionState::QUARANTINE ||
        state_ == SessionState::FLUSHING   ||
        state_ == SessionState::CLOSED) {
        return false;
    }

    // 1. Warp Score Calculation [E-8]
    float base_weight = 0.0f;
    switch (decision.action) {
        case PolicyAction::DENY:        base_weight = WARP_WEIGHT_DENY; break;
        case PolicyAction::FLAG:        base_weight = WARP_WEIGHT_FLAG; break;
        case PolicyAction::REQUIRE_MFA: base_weight = WARP_WEIGHT_MFA;  break;
        case PolicyAction::ALLOW:       base_weight = WARP_WEIGHT_ALLOW; break;
        default:                        base_weight = 0.0f; break;
    }

    // Apply risk multiplier from policy metadata
    float delta = base_weight * decision.risk_weight;
    warp_score_ = std::max(0.0f, warp_score_ + delta);

    // 2. Buffer payload for Entropy Management
    payload_buffer_.push_back(decision.payload_hash);
    if (payload_buffer_.size() > MAX_BUFFER) {
        payload_buffer_.pop_front();
    }

    // 3. State Transition Logic
    // Quarantine is triggered at 3x the threshold for absolute fail-stop
    if (warp_score_ >= (warp_threshold_ * 3.0f)) {
        transition(SessionState::QUARANTINE, "warp_critical_threshold");
        initiate_flush(now_ms);
        return false;
    } 
    // Suspect state triggered at 1x threshold
    else if (warp_score_ >= warp_threshold_ && state_ == SessionState::ACTIVE) {
        transition(SessionState::SUSPECT, "warp_elevated_risk");
    }
    // Recovery: Decay allows return to ACTIVE if behavior stabilizes
    else if (warp_score_ < (warp_threshold_ * 0.5f) && state_ == SessionState::SUSPECT) {
        transition(SessionState::ACTIVE, "warp_stabilized");
    }

    // Log the event for audit/transparency
    log_event({ now_ms, "POLICY_DECISION", decision.payload_hash,
                action_str(decision.action) + " weight=" + std::to_string(delta) });

    // 4. Entropy Flush Trigger
    // We flush on any DENY or when the entropy buffer is full to prevent probing
    if (decision.action == PolicyAction::DENY || payload_buffer_.size() >= MAX_BUFFER) {
        initiate_flush(now_ms);
    }

    return (state_ != SessionState::QUARANTINE && decision.action != PolicyAction::DENY);
}

void Session::initiate_flush(uint64_t now_ms) {
    // If we aren't already terminal, move to FLUSHING
    if (state_ != SessionState::QUARANTINE && state_ != SessionState::CLOSED) {
        transition(SessionState::FLUSHING, "entropy_flush_start");
    }

    // Generate unique incident ID using SHA256 context
    std::string salt = session_id_ + std::to_string(now_ms);
    std::string incident_id = crypto::SimpleHashProvider::instance().sha256(salt);
    
    std::vector<std::string> tainted(payload_buffer_.begin(), payload_buffer_.end());
    payload_buffer_.clear();
    
    if (on_flush_) {
        on_flush_(session_id_, incident_id, tainted);
    }

    // If we were just flushing (not quarantined), move to RESYNC to await re-handshake
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
    warp_score_ = 0.0f; // Reset health on successful re-authentication
    payload_buffer_.clear();
    transition(SessionState::ACTIVE, "resync_successful");
}

void Session::transition(SessionState next, const std::string& reason) {
    if (state_ == next) return;

    std::string detail = state_str(state_) + " -> " +
                         state_str(next) + " reason=" + reason + 
                         " score=" + std::to_string(warp_score_);
    
    state_ = next;
    log_event({ 0, "STATE_TRANSITION", "", detail });
}

void Session::close() {
    transition(SessionState::CLOSED, "session_terminated");
}

bool Session::is_active() const {
    return (state_ == SessionState::ACTIVE || state_ == SessionState::SUSPECT);
}

void Session::require_state(SessionState expected, const std::string& op) const {
    if (state_ != expected) {
        throw std::runtime_error("Session error: " + op + " invalid in " + state_str(state_));
    }
}

void Session::log_event(SessionEvent e) {
    event_log_.push_back(std::move(e));
}

} // namespace uml001