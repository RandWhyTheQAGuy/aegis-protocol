/*
 * Copyright 2026 Aegis Protocol Authors
 * Apache 2.0 License
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace uml001 {

/**
 * @brief POD snapshot of the BFT clock state for Redis promotion.
 */
struct SharedClockState {
    uint64_t last_agreed_time_ms = 0;
    double   current_drift_ppm = 0.0;
    uint64_t version_counter = 0;      // For optimistic concurrency
    char     active_signer_id[64] = {0};
    
    // Serializes state for Redis storage
    std::string serialize() const {
        return std::string(reinterpret_cast<const char*>(this), sizeof(SharedClockState));
    }

    static SharedClockState deserialize(const std::string& data) {
        SharedClockState state;
        if (data.size() == sizeof(SharedClockState)) {
            fallback_memcpy(&state, data.data(), sizeof(SharedClockState));
        }
        return state;
    }

private:
    static void fallback_memcpy(void* dest, const void* src, size_t n) {
        auto d = static_cast<char*>(dest);
        auto s = static_cast<const char*>(src);
        while (n--) *d++ = *s++;
    }
};

} // namespace uml001