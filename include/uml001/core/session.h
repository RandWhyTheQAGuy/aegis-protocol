#pragma once

#include "uml001/core/policy.h"
#include <string>
#include <vector>
#include <deque>
#include <functional>
#include <atomic>

namespace uml001 {

enum class SessionState {
    INIT,
    ACTIVE,
    SUSPECT,      // Warp Score > Threshold 1
    QUARANTINE,   // Warp Score > Threshold 2 (Fail-Closed)
    FLUSHING,     // Entropy Reset in progress
    RESYNC,       // Recovering from Clock Drift
    CLOSED
};

// [E-8] Warp Weights for State Transitions
static constexpr float WARP_WEIGHT_ALLOW   = -0.1f; // Successful clean ops reduce score
static constexpr float WARP_WEIGHT_FLAG    =  0.5f;
static constexpr float WARP_WEIGHT_DENY    =  1.0f;
static constexpr float WARP_WEIGHT_MFA     =  0.2f;

// [E-8] Warp Score Bounds and Decay
static constexpr float WARP_SCORE_MAX      = 100.0f; // Prevent unbounded growth
static constexpr float WARP_DECAY_RATE     = 0.01f;  // 1% decay per decision
static constexpr uint64_t WARP_DECAY_TIME_MS = 60000; // Decay every minute

struct SessionEvent {
    uint64_t timestamp;
    std::string type;
    std::string payload_hash;
    std::string details;
};

class Session {
public:
    using FlushCallback = std::function<void(const std::string&, const std::string&, const std::vector<std::string>&)>;

    Session(std::string session_id,
            std::string peer_model_id,
            float       warp_threshold,
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
    float       warp_threshold_; // Base threshold for SUSPECT
    FlushCallback on_flush_;
    
    SessionState state_;
    float        warp_score_;
    uint64_t     last_decision_time_ms_; // For time-based decay
    
    std::deque<std::string>  payload_buffer_;
    std::vector<SessionEvent> event_log_;
    const size_t MAX_BUFFER = 100;
};

} // namespace uml001