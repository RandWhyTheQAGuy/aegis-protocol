#include "aegis/integration/datadog_logger.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace aegis::integration {

DatadogLogger::DatadogLogger(const std::string& agent_host, int agent_port)
    : host_(agent_host), port_(agent_port) {}

void DatadogLogger::log_event(uml001::LogDestination dest, const std::string& message) {
    if (dest == uml001::LogDestination::STDOUT) {
        std::cout << "[DATADOG-LOG] " << message << std::endl;
    } else if (dest == uml001::LogDestination::DATADOG_UDP) {
        // Wrap message in Datadog-friendly JSON or DogStatsD format
        std::string payload = "_e{5,15}:Event|" + message + "|h:" + host_;
        send_udp(payload);
    }
}

void DatadogLogger::send_udp(const std::string& payload) {
    // Basic UDP implementation for Datadog Agent communication
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port_);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    sendto(sock, payload.c_str(), payload.size(), 0,
           (const struct sockaddr*)&servaddr, sizeof(servaddr));
    close(sock);
}

} // namespace aegis::integration