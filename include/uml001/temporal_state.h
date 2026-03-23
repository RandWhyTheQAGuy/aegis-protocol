// ============================================================
// 3. Temporal State Machine
// File: include/uml001/temporal_state.h
// ============================================================
#pragma once

#include <cstdint>

namespace uml001 {

enum class TemporalState {
    SYNCHRONIZED,
    CACHED,
    DEGRADED,
    UNTRUSTED
};

class TemporalStateMachine {
public:
    void update(uint64_t time_since_last_quorum_ms)
    {
        if (time_since_last_quorum_ms < 100)
            state_ = TemporalState::SYNCHRONIZED;
        else if (time_since_last_quorum_ms < 2000)
            state_ = TemporalState::CACHED;
        else if (time_since_last_quorum_ms < 10000)
            state_ = TemporalState::DEGRADED;
        else
            state_ = TemporalState::UNTRUSTED;
    }

    TemporalState state() const { return state_; }

    bool allow_writes() const
    {
        return state_ == TemporalState::SYNCHRONIZED ||
               state_ == TemporalState::CACHED;
    }

    bool allow_reads() const
    {
        return state_ != TemporalState::UNTRUSTED;
    }

private:
    TemporalState state_{TemporalState::UNTRUSTED};
};

} // namespace uml001