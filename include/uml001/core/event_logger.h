#pragma once

#include <string>

namespace uml001 {

/**
 * @brief Logical destination for structured event logging.
 */
enum class LogDestination {
    TRANSPARENCY_LOG,
    METRICS,
    DEBUG
};

/**
 * @brief Abstract interface for event logging backends.
 */
class IEventLogger {
public:
    virtual ~IEventLogger() = default;

    virtual void log_event(LogDestination dest,
                           const std::string& message) = 0;
};

} // namespace uml001