#pragma once

#include "uml001/shared_state.h"
#include "uml001/core/clock_store.h"
#include <sw/redis++/redis++.h>
#include <optional>
#include <mutex>

namespace uml001 {

/**
 * @brief Redis-backed implementation of IClockStore.
 *
 * Uses WATCH/MULTI/EXEC for optimistic concurrency on a single key.
 */
class RedisSharedStore : public IClockStore {
public:
    explicit RedisSharedStore(const std::string& connection_uri);

    /**
     * @brief Performs a WATCH/MULTI/EXEC transaction to promote state.
     * Returns true if the promotion succeeded (no concurrent write).
     */
    bool watch_and_commit(const SharedClockState& new_state) override;

    /**
     * @brief Fetches the current global state from Redis.
     */
    std::optional<SharedClockState> get_latest_state() override;

private:
    sw::redis::Redis redis_;
    const std::string key_name_ = "aegis:clock:shared_state";
};

} // namespace uml001