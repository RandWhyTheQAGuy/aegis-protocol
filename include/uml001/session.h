// session.h
    #pragma once
    #include "policy.h"
    #include <deque>
    #include <functional>
    #include <stdexcept>

    namespace uml001 {

    enum class SessionState {
        INIT, ACTIVE, SUSPECT, QUARANTINE, FLUSHING, RESYNC, CLOSED
    };

    inline std::string state_str(SessionState s) {
        switch (s) {
            case SessionState::INIT:       return "INIT";
            case SessionState::ACTIVE:     return "ACTIVE";
            case SessionState::SUSPECT:    return "SUSPECT";
            case SessionState::QUARANTINE: return "QUARANTINE";
            case SessionState::FLUSHING:   return "FLUSHING";
            case SessionState::RESYNC:     return "RESYNC";
            case SessionState::CLOSED:     return "CLOSED";
        }
        return "UNKNOWN";
    }

    struct SessionEvent {
        uint64_t    timestamp;
        std::string event_type;   // "PAYLOAD", "DECISION", "STATE_CHANGE", "FLUSH"
        std::string payload_hash;
        std::string detail;
    };

    // Callback invoked when Entropy Flush is triggered.
    // Receives: session_id, incident_id, list of tainted payload hashes.
    using FlushCallback = std::function<void(
        const std::string&,               // session_id
        const std::string&,               // incident_id
        const std::vector<std::string>&   // tainted payload hashes
    )>;

    // ---------------------------------------------------------------------------
    // Session: tracks state for one peer connection
    // ---------------------------------------------------------------------------
    class Session {
    public:
        Session(std::string session_id,
                std::string peer_model_id,
                float       warp_threshold = 3.0f,
                FlushCallback on_flush     = nullptr)
            : session_id_(std::move(session_id))
            , peer_model_id_(std::move(peer_model_id))
            , warp_threshold_(warp_threshold)
            , on_flush_(std::move(on_flush))
            , state_(SessionState::INIT)
            , warp_score_(0.0f) {}

        // Call after successful HELLO_CONFIRM exchange
        void activate() {
            require_state(SessionState::INIT, "activate");
            transition(SessionState::ACTIVE, "handshake complete");
        }

        // Process a policy decision for an inbound payload.
        // Returns false if the session has been quarantined (payload rejected).
        bool process_decision(const PolicyDecision& decision, uint64_t now) {
            if (state_ == SessionState::QUARANTINE ||
                state_ == SessionState::FLUSHING   ||
                state_ == SessionState::RESYNC      ||
                state_ == SessionState::CLOSED) {
                return false;
            }

            // Track payload hash for potential flush
            payload_buffer_.push_back(decision.payload_hash);
            if (payload_buffer_.size() > MAX_BUFFER) payload_buffer_.pop_front();

            // Accumulate Warp Score
            switch (decision.action) {
                case PolicyAction::DENY:
                    warp_score_ += 1.0f;
                    break;
                case PolicyAction::FLAG:
                    warp_score_ += 0.5f;
                    break;
                case PolicyAction::ALLOW:
                    warp_score_ = std::max(0.0f, warp_score_ - 0.1f);
                    break;
            }

            log_event({ now, "DECISION", decision.payload_hash,
                        action_str(decision.action) + " rule=" +
                        decision.matched_rule_id });

            // State transitions
            if (warp_score_ >= warp_threshold_) {
                transition(SessionState::QUARANTINE, "warp threshold exceeded");
                initiate_flush(now);
                return false;
            }

            if (state_ == SessionState::ACTIVE &&
                decision.action == PolicyAction::DENY) {
                transition(SessionState::SUSPECT, "first DENY");
            } else if (state_ == SessionState::SUSPECT &&
                       warp_score_ < 1.0f) {
                transition(SessionState::ACTIVE, "warp score decayed");
            }

            return decision.action != PolicyAction::DENY;
        }

        void complete_flush() {
            require_state(SessionState::FLUSHING, "complete_flush");
            transition(SessionState::RESYNC, "flush complete");
        }

        void reactivate() {
            require_state(SessionState::RESYNC, "reactivate");
            warp_score_ = 0.0f;
            payload_buffer_.clear();
            transition(SessionState::ACTIVE, "re-handshake complete");
        }

        void close() {
            transition(SessionState::CLOSED, "closed");
        }

        SessionState        state()         const { return state_; }
        float               warp_score()    const { return warp_score_; }
        const std::string&  session_id()    const { return session_id_; }
        const std::string&  peer_model_id() const { return peer_model_id_; }
        const std::vector<SessionEvent>& event_log() const { return event_log_; }

    private:
        static constexpr size_t MAX_BUFFER = 256;

        std::string   session_id_;
        std::string   peer_model_id_;
        float         warp_threshold_;
        FlushCallback on_flush_;
        SessionState  state_;
        float         warp_score_;
        std::deque<std::string>  payload_buffer_;
        std::vector<SessionEvent> event_log_;

        void transition(SessionState next, const std::string& reason) {
            std::string detail = state_str(state_) + " -> " +
                                 state_str(next) + " (" + reason + ")";
            state_ = next;
            log_event({ 0, "STATE_CHANGE", "", detail });
        }

        void initiate_flush(uint64_t now) {
            transition(SessionState::FLUSHING, "entropy flush initiated");
            std::string incident_id = sha256_hex(
                session_id_ + std::to_string(now));
            std::vector<std::string> tainted(
                payload_buffer_.begin(), payload_buffer_.end());
            payload_buffer_.clear();
            log_event({ now, "FLUSH", "", "incident=" + incident_id });
            if (on_flush_)
                on_flush_(session_id_, incident_id, tainted);
        }

        void require_state(SessionState expected, const std::string& op) const {
            if (state_ != expected)
                throw std::runtime_error(
                    "Session::" + op + " called in invalid state: " +
                    state_str(state_));
        }

        void log_event(SessionEvent e) {
            event_log_.push_back(std::move(e));
        }
    };

    } // namespace uml001
