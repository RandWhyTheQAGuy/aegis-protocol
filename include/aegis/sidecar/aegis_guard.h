#pragma once

#include "uml001/core/passport.h"
#include "uml001/security/vault.h"
#include <memory>
#include <string>

namespace aegis::sidecar {

class AegisGuard {
public:
    AegisGuard(const std::string& agent_id,
               std::shared_ptr<uml001::ColdVault> vault);

    bool validate_request(const std::string& request_payload,
                         const uml001::Passport& passport);

private:
    std::string agent_id_;
    std::shared_ptr<uml001::ColdVault> vault_;
};

} // namespace aegis::sidecar