/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ------------------------------------------------------------------------
 * Design: IClock Interface & Implementations (UML-001)
 * ------------------------------------------------------------------------
 * This interface decouples time-consumers (Vault, Passport, Sidecar) from
 * time-providers (NTP, BFT Quorum, OS Clock). 
 *
 */

#pragma once

#include <cstdint>
#include <string>
#include <chrono>
#include <atomic>

namespace uml001 {

/**
 * @brief Represents the health and synchronization state of the clock provider.
 */
enum class ClockStatus {
    UNKNOWN,      ///< Initial state, no sync attempted
    SYNCHRONIZED, ///< Locked to a trusted source (BFT Quorum or NTP)
    DEGRADED,     ///< Source is reachable but drift is exceeding safety bounds
    FAULT         ///< Source is unreachable or cryptographic verification failed
};

/**
 * @brief Abstract base class for all UML-001 compliant time sources.
 */
class IClock {
public:
    virtual ~IClock() = default;

    virtual uint64_t now_unix() const = 0;
    virtual uint64_t now_ms() const = 0;
    virtual bool is_synchronized() const = 0;
    virtual uint64_t last_sync_unix() const = 0;
    virtual ClockStatus status() const = 0;
    virtual std::string source_id() const = 0;
};

/**
 * @brief Standard System Clock implementation for Dev/CI environments.
 * Provides a stable fallback when BFT Quorum nodes are unavailable.
 */
class SystemClock : public IClock {
public:
    SystemClock() = default;

    uint64_t now_unix() const override {
        auto now = std::chrono::system_clock::now().time_since_epoch();
        uint64_t current = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        return enforce_monotonic(current);
    }

    uint64_t now_ms() const override {
        auto now = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    }

    bool is_synchronized() const override { return true; }
    
    uint64_t last_sync_unix() const override { return now_unix(); }

    ClockStatus status() const override { return ClockStatus::SYNCHRONIZED; }

    std::string source_id() const override { return "LOCAL_SYSTEM_CLOCK"; }

private:
    // [R-1] Monotonicity Enforcement
    mutable std::atomic<uint64_t> floor_{0};

    uint64_t enforce_monotonic(uint64_t t) const {
        uint64_t prev = floor_.load();
        while (t > prev && !floor_.compare_exchange_weak(prev, t)) {}
        return (t < prev) ? prev : t;
    }
};

} // namespace uml001