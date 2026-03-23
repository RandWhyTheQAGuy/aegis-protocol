#include "uml001/memory_clock_store.h"

namespace uml001 {

bool MemoryClockStore::watch_and_commit(const SharedClockState& new_state) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_) {
        // Preserve optimistic concurrency semantics: reject stale updates.
        if (new_state.version_counter <= state_->version_counter) {
            return false;
        }
    }

    state_ = new_state;
    return true;
}

std::optional<SharedClockState> MemoryClockStore::get_latest_state() {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

} // namespace uml001
