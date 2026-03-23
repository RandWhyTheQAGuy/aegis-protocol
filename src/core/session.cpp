#include "uml001/core/session.h"
#include <chrono>

namespace uml001 {

Session::Session(const std::string& session_id, const Passport& passport)
    : id_(session_id), passport_(passport), active_(true) {
    start_time_ = std::chrono::system_clock::now();
}

bool Session::is_valid() const {
    auto now = std::chrono::system_clock::now();
    // Check if the passport has expired
    if (passport_.expires_at < std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count()) {
        return false;
    }
    return active_;
}

void Session::terminate() {
    active_ = false;
}

} // namespace uml001