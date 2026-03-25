#pragma once

#include "uml001/security/transparency_log.h"
#include <string>
#include <vector>

namespace aegis {
namespace integration {

/**
 * @brief DatadogLogger provides observability integration for Aegis Protocol
 * 
 * Logs security events and transparency entries to Datadog agent via UDP
 */
class DatadogLogger {
public:
    DatadogLogger(const std::string& agent_host, int agent_port);
    ~DatadogLogger() = default;

    /**
     * @brief Log a security event to Datadog
     * @param event_type The type of security event
     * @param message The event message  
     */
    void log_event(const std::string& event_type,
                   const std::string& message);

private:
    std::string host_;
    int port_;
    void send_udp(const std::string& payload);
};

} // namespace integration
} // namespace aegis