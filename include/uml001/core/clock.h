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
 * Design: IClock Interface (UML-001)
 * ------------------------------------------------------------------------
 * This interface decouples time-consumers (Vault, Passport, Sidecar) from
 * time-providers (NTP, BFT Quorum, OS Clock). 
 *
 * Security Requirements:
 * [R-1] Monotonicity: now_unix() must never return a value lower than a 
 * previous call during the same process lifetime.
 * [R-2] Integrity: Implementation must provide a 'synchronized' status 
 * to alert callers if the time source is currently untrusted.
 */

#pragma once

#include <cstdint>
#include <string>

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

    /**
     * @brief Returns the current Unix timestamp in seconds.
     * @return uint64_t Unix epoch time.
     */
    virtual uint64_t now_unix() const = 0;

    /**
     * @brief Returns the current Unix timestamp in milliseconds for higher precision tasks.
     * @return uint64_t Unix epoch time (ms).
     */
    virtual uint64_t now_ms() const = 0;

    /**
     * @brief Check if the clock is currently synchronized with its trusted source.
     * @return true if status is SYNCHRONIZED.
     */
    virtual bool is_synchronized() const = 0;

    /**
     * @brief Returns the timestamp of the last successful synchronization event.
     */
    virtual uint64_t last_sync_unix() const = 0;

    /**
     * @brief Returns the current status of the clock.
     */
    virtual ClockStatus status() const = 0;

    /**
     * @brief Returns a human-readable identifier for the clock source (e.g., "BFT-Quorum", "OS-System").
     */
    virtual std::string source_id() const = 0;
};

} // namespace uml001