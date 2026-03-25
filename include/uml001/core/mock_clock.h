#pragma once

#include "uml001/core/clock.h"

namespace uml001 {

/**
 * @brief Mock clock implementation for CI/CD testing.
 * Provides deterministic timestamps without BFT Quorum dependency.
 */
class MockClock : public IClock {
public:
    MockClock() = default;
    ~MockClock() override = default;

    /**
     * @brief Returns fixed UNIX time in seconds (2025-02-18)
     */
    uint64_t now_unix() const override { 
        return 1740000000ULL; 
    }

    /**
     * @brief Returns fixed UNIX time in milliseconds
     */
    uint64_t now_ms() const override { 
        return 1740000000000ULL; 
    }

    /**
     * @brief Mock clock is always synchronized in testing
     */
    bool is_synchronized() const override {
        return true;
    }

    /**
     * @brief Last sync time (fixed for determinism)
     */
    uint64_t last_sync_unix() const override {
        return 1740000000ULL;
    }

    /**
     * @brief Mock clock is always synchronized in testing
     */
    ClockStatus status() const override { 
        return ClockStatus::SYNCHRONIZED; 
    }

    /**
     * @brief Identifier for this clock source
     */
    std::string source_id() const override {
        return "MockClock-CI";
    }
};

} // namespace uml001
