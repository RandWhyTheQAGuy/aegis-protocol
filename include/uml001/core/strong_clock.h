#pragma once

#include "uml001/clock.h"
#include <atomic>
#include <chrono>

namespace uml001 {

/**
 * @brief High-precision local clock used as the foundation for BFT drift calculations.
 */
class OsStrongClock : public IClock {
public:
    OsStrongClock();

    uint64_t now_unix() const override;
    uint64_t now_ms() const override;
    bool is_synchronized() const override { return synchronized_.load(); }
    uint64_t last_sync_unix() const override { return last_sync_.load(); }
    ClockStatus status() const override;
    std::string source_id() const override { return "OS_SYSTEM_STRONG"; }

    // Internal update for the background sync loop
    void mark_synchronized(bool sync);

private:
    std::atomic<bool> synchronized_;
    std::atomic<uint64_t> last_sync_;
};

} // namespace uml001