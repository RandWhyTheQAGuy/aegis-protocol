#pragma once
<<<<<<< HEAD

#include "uml001/core/policy.h"
=======
enum class SessionState { INIT, ACTIVE, SUSPECT, QUARANTINE, FLUSHING, RESYNC, CLOSED };
enum class SessionState {
//
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
#include <string>
#include <vector>
#include <deque>
#include <functional>
#include <atomic>
<<<<<<< HEAD

namespace uml001 {

enum class SessionState {
=======
#include "uml001/core/policy.h"

namespace uml001 {

    
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
    INIT,
    ACTIVE,
    SUSPECT,      // Warp Score > Threshold 1
    QUARANTINE,   // Warp Score > Threshold 2 (Fail-Closed)
    FLUSHING,     // Entropy Reset in progress
    RESYNC,       // Recovering from Clock Drift
    CLOSED
<<<<<<< HEAD
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

=======
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
<<<<<<< HEAD
    
=======
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
    /**
     * @brief Processes a policy decision and updates the Warp Score.
     * If score exceeds threshold, transitions to SUSPECT or QUARANTINE.
     */
    bool process_decision(const PolicyDecision& decision, uint64_t now_ms);
<<<<<<< HEAD
    
=======
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
    void initiate_flush(uint64_t now_ms);
    void complete_flush();
    void reactivate();
    void close();

    // Accessors
    bool is_active() const { return state_ == SessionState::ACTIVE || state_ == SessionState::SUSPECT; }
    SessionState state() const { return state_; }
    float warp_score() const { return warp_score_; }
<<<<<<< HEAD
    
=======

>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
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
    std::deque<std::string>  payload_buffer_;
    const size_t MAX_BUFFER = 100;
};

} // namespace uml001
    static std::string state_str(SessionState s);

private:
    void transition(SessionState next, const std::string& reason);
<<<<<<< HEAD
    void initiate_flush(uint64_t now_ms);
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
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

<<<<<<< HEAD
} // namespace uml001
=======
}
=======
    void log_event(const std::string& type, const std::string& detail, uint64_t ts);

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
>>>>>>> cc5bbf5 (WIP: continued clean integration and BFT hardening updates)
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
