/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include "uml001/core/pulse_manager.h"
#include <chrono>

namespace uml001 {

PulseManager::PulseManager(IClock& clock)
    : clock_(clock), last_success_(now_ms()) {
}

PulseManager::~PulseManager() {
    stop();
}

void PulseManager::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread([this]() { this->loop(); });
}

void PulseManager::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

TemporalState PulseManager::current_state() const {
    return tsm_.state();
}

void PulseManager::loop() {
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
        // Call update with 2 arguments: uncertainty (converted from delta) and drift (0.0)
        tsm_.update(static_cast<double>(delta), 0.0);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

uint64_t PulseManager::now_ms() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace uml001
