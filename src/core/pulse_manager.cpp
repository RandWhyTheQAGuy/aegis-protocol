/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/core/clock.h"
#include "uml001/core/temporal_state.h"
#include <thread>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <vector>

namespace uml001 {

// Forward declaration of the clock type used by PulseManager
class RemoteQuorumClock;

/**
 * @brief PulseManager maintains the heartbeat of the BFT Quorum connection.
 * It periodically polls the clock and updates the TemporalStateMachine.
 */
class PulseManager {
public:
    PulseManager(IClock& clock)
        : clock_(clock)
    {}

    ~PulseManager() {
        stop();
    }

    void start() {
        if (running_) return;
        running_ = true;
        thread_ = std::thread([this]() { this->loop(); });
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    TemporalState current_state() const {
        return tsm_.state();
    }

private:
    void loop() {
        while (running_) {
            try {
                // Poll the clock to verify synchronization
                clock_.now_unix();
                last_success_ = now_ms();
            } catch (...) {
                // On failure, we don't update last_success_, 
                // causing the TSM to eventually degrade.
            }

            uint64_t delta = now_ms() - last_success_;
            tsm_.update(delta);

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    uint64_t now_ms() const {
        // Use injected clock for time instead of std::chrono
        return clock_->now_ms();
    }

    IClock& clock_;
    TemporalStateMachine tsm_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    uint64_t last_success_{0};
};

} // namespace uml001