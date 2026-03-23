#pragma once

#include "uml001/core/clock_store.h"
#include <optional>
#include <mutex>

namespace uml001 {

/**
 * @brief Simple in-memory implementation of IClockStore.
 *
 * Always available (no external dependencies). Suitable as a default or
 * for tests and air-gapped environments.
 */
class MemoryClockStore : public IClockStore {
public:
    MemoryClockStore() = default;

    bool watch_and_commit(const SharedClockState& new_state) override;
    std::optional<SharedClockState> get_latest_state() override;

private:
    mutable std::mutex mutex_;
    std::optional<SharedClockState> state_;
};

} // namespace uml001
