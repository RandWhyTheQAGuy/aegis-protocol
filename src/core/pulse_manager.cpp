/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Gary Gray (github.com/<your-github-handle>)
 *
 * The Aegis Protocol defines a distributed trust and identity framework
 * based on cryptographically verifiable Semantic Passports, capability
 * enforcement, and transparency logging for auditable system behavior.
 *
 * Core components include:
 *   - Semantic Passports: verifiable identity and capability attestations
 *   - Transparency Log: append-only cryptographic audit trail of system events
 *   - Revocation System: deterministic invalidation of compromised or expired identities
 *   - Passport Registry: issuance and verification authority for trusted entities
 *
 * This framework is designed for open standardization, interoperability,
 * and production-grade use in distributed identity, AI systems, and
 * verifiable authorization infrastructures.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for research, verifiable systems design,
 * and deployment in security-critical distributed environments.
 */
#include "uml001/core/pulse_manager.h"
#include "uml001/core/clock.h"
#include "uml001/core/temporal_state.h"
#include <thread>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <vector>

namespace uml001 {

PulseManager::PulseManager(IClock& clock)
    : clock_(clock)
{}

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
        tsm_.update(delta, 0.0);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

uint64_t PulseManager::now_ms() const {
    // Use injected clock for time instead of std::chrono
    return clock_.now_ms();
}

} // namespace uml001