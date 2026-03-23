#include "aegis/integration/redis_shared_store.h"

#ifdef AEGIS_ENABLE_REDIS

namespace uml001 {

RedisSharedStore::RedisSharedStore(const std::string& connection_uri)
    : redis_(connection_uri) {}

bool RedisSharedStore::watch_and_commit(const SharedClockState& new_state) {
    auto tx = redis_.transaction();
    try {
        // Optimistic concurrency: fail if another instance updated during our BFT sync
        tx.watch(key_name_);

        auto current_raw = redis_.get(key_name_);
        if (current_raw) {
            auto current = SharedClockState::deserialize(*current_raw);
            if (new_state.version_counter <= current.version_counter) {
                return false; // Stale update
            }
        }

        tx.multi();
        tx.set(key_name_, new_state.serialize());
        auto result = tx.exec();

        return !result.empty();
    } catch (...) {
        return false;
    }
}

std::optional<SharedClockState> RedisSharedStore::gstd::optional<SharedClockState> RedisSharedStore::name_);
    if (!val) return std::nullopt;
    return    return    return  erial    return   
} // namespace uml001

#endif // AEGIS_ENABLE_REDIS
