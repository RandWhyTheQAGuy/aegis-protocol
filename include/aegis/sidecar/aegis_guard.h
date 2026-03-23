#pragma once

#include <string>
#include <memory>
#include "uml001/core/passport.h"
#include "uml001/security/vault.h"

namespace aegis {

/**
 * @brief The AegisGuard acts as a security proxy for the AI agent.
 */
class AegisGuard {
public:
    struct Config {
        std::string agent_id;      // This fixes the 'config_agent_id' error
        std::string vault_path;
        bool enforcement_enabled = true;
    };

    explicit AegisGuard(Config config, std::shared_ptr<uml001::IVault> vault);

    bool validate_action(const std::string& action_type, const std::string& resource);
    std::string get_agent_id() const { return config_.agent_id; }

private:
    Config config_;
    std::shared_ptr<uml001::IVault> vault_;
};

} // namespace aegis