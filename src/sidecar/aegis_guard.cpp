#include "aegis/sidecar/aegis_guard.h"
#include <iostream>

namespace aegis::sidecar {

AegisGuard::AegisGuard(const std::string& agent_id,
                       std::shared_ptr<uml001::ColdVault> vault)
    : agent_id_(agent_id), vault_(vault) {}

bool AegisGuard::validate_request(const std::string& request_payload,
                                 const uml001::Passport& passport) {
    // Ensure the passport belongs to this agent
    if (passport.model_id != agent_id_) {
        return false;
    }

    // Logic for runtime sidecar validation goes here
    std::cout << "[AegisGuard] Validating request for agent: " << agent_id_ << std::endl;
    return true;
}

} // namespace aegis::sidecar