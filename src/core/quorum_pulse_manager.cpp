/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/bft/remote_quorum_clock.h"
#include <thread>
#include <atomic>

namespace uml001 {

class QuorumPulseManager {
public:
    QuorumPulseManager(RemoteQuorumClock& clock) : clock_(clock), running_(false) {}

    void start() {
        running_ = true;
        pulse_thread_ = std::thread([this]() {
            while (running_) {
                try {
                    // Standardized to now_ms() per IClock interface
                    last_time_ = clock_.now_ms();
                } catch (...) {
                    // Handle sync failure
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        });
    }

    void stop() {
        running_ = false;
        if (pulse_thread_.joinable()) pulse_thread_.join();
    }

private:
    RemoteQuorumClock& clock_;
    std::atomic<bool> running_;
    std::thread pulse_thread_;
    uint64_t last_time_ = 0;
};

} // namespace uml001