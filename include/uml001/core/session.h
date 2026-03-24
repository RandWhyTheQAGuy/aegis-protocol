#pragma once
#include <string>
#include <vector>
#include <deque>
#include <functional>
#include "uml001/core/policy.h"

namespace uml001 {

enum class SessionState { INIT, ACTIVE, SUSPECT, QUARANTINE, FLUSHING, RESYNC, CLOSED };

struct SessionEvent {
    uint64_t timestamp;
    std::string type;
    std::string payload_hash;
    std::string detail;
};

// Flush callback: (session_id, incident_id, tainted_payload_hashes)
using FlushCallback = std::function<void(const std::string&, const std::string&, const std::vector<std::string>&)>;

// Warp Score Weights (SECURITY CRITICAL)
static constexpr float WARP_WEIGHT_ALLOW     = -0.1f;
static constexpr float WARP_WEIGHT_FLAG      =  0.5f;
static constexpr float WARP_WEIGHT_MFA       =  0.3f;
static constexpr float WARP_WEIGHT_DENY      =  1.0f;
static constexpr size_t MAX_BUFFER           = 1024;

class Session {
public:
    Session(std::string session_id, std::string peer_model_id, float warp_threshold, 
            FlushCallback on_flush);

    void activate();
    bool process_decision(const PolicyDecision& decision, uint64_t now_ms);
    void complete_flush();
    void reactivate();
    void close();

    SessionState state() const { return state_; }
    float warp_score() const { return warp_score_; }
    bool is_active() const;
    
    static std::string state_str(SessionState s);

private:
    void transition(SessionState next, const std::string& reason);
    void initiate_flush(uint64_t now_ms);
    void require_state(SessionState expected, const std::string& op) const;
    void log_event(const std::string& type, const std::string& detail, uint64_t ts, 
                   const std::string& payload_hash = "");

    std::string session_id_;
    std::string peer_model_id_;
    float warp_threshold_;
    float warp_score_ = 0.0f;
    SessionState state_;
    
    std::deque<std::string> payload_buffer_;
    std::vector<SessionEvent> event_log_;
    FlushCallback on_flush_;
};

}