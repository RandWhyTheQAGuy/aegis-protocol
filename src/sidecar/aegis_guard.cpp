#include "aegis/sidecar/aegis_guard.h"
#include <iostream>

namespace aegis {

AegisGuard::AegisGuard(Config config, std::shared_ptr<uml001::IVault> vault)
    : config_(config), vault_(vault) {
    if (config_.agent_id.empty()) {
        throw std::runtime_error("AegisGuard Error: agent_id must be specified in config.");
    }
}

bool AegisGuard::validate_action(const std::string& action_type, const std::string& resource) {
    // Logic to check if the AI agent is allowed to perform this action
    std::cout << "[AegisGuard] Validating action: " << action_type 
              << " on resource: " << resource << " for Agent: " << config_.agent_id << std::endl;
    
    return true; // Simple pass-through for now
}

} // namespace aegis