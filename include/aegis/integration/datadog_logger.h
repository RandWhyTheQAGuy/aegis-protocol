#pragma once

#include "uml001/security/transparency_log.h"
#include <string>
#include <vector>

namespace aegis::integration {

// DatadogLogger implements the core IEventLogger interface
class DatadogLogger : public uml001::IEventLogger {
public:
    DatadogLogger(const std::string& agent_host, int agent_port);
    ~DatadogLogger() override = default;

    // Implementation of the virtual method defined in transparency_log.h
    void log_event(uml001::LogDestination dest, 
                   const std::string& message) override;

private:
    std::string host_;
    int port_;
    void send_udp(const std::string& payload);
};

} // namespace aegis::integration