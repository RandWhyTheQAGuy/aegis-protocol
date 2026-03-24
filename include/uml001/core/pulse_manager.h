#pragma once

#include "uml001/core/clock.h"
#include "uml001/core/temporal_state.h"
#include <thread>
#include <atomic>

namespace uml001 {

/**
 * @brief PulseManager maintains the heartbeat of the BFT Quorum connection.
 * It periodically polls the clock and updates the TemporalStateMachine.
 * 
 * [E-3] "Connected Integrity": Validates that the Quorum clock is still responsive.
 */
class PulseManager {
public:
    explicit PulseManager(IClock& clock);
    ~PulseManager();

    void start();
    void stop();

    TemporalState current_state() const;

private:
    void loop();
    uint64_t now_ms() const;

    IClock& clock_;
    TemporalStateMachine tsm_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    uint64_t last_success_{0};
};

} // namespace uml001
