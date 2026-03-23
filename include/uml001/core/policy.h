#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace uml001 {

enum class PolicyAction {
    ALLOW = 0,
    DENY,
    FLAG,
    REQUIRE_MFA
};

struct PolicyDecision {
    PolicyAction action = PolicyAction::DENY;
    std::string reason;
    std::string policy_id;
    uint32_t risk_score = 0;
};

struct ResourceConstraint {
    std::string resource_id;
    std::string action; 
    bool allowed;
};

struct Policy {
    std::string policy_id;
    std::string version;
    std::vector<ResourceConstraint> constraints;
    std::map<std::string, std::string> metadata;

    std::string compute_hash() const;
};

} // namespace uml001