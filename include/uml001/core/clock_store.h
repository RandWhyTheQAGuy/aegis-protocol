#pragma once

#include "uml001/shared_state.h"
#include <optional>

namespace uml001 {

/**
 * @brief Abstract interface for clock state backends (Redis, memory, etc.).
 */
class IClockStore {
public:
    virtual ~IClockStore() = default;

    /**
     * @brief Atomically attempts to promote a new shared clock state.
     * @return true if the promotion succeeded (no conflicting concurrent write).
     */
    virtual bool watch_and_commit(const SharedClockState& new_state) = 0;

    /**
     * @brief Fetches the latest known shared clock state, if any.
     */
    virtual std::optional<SharedClockState> get_latest_state() = 0;
};

} // namespace uml001
