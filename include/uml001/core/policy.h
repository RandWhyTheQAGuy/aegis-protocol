#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <optional>
#include "uml001/security/zk_proofs.h"

namespace uml001 {

enum class PolicyAction {
    ALLOW = 0,
    DENY,
    FLAG,
    REQUIRE_MFA
};

inline std::string action_str(PolicyAction a) {
    switch (a) {
        case PolicyAction::ALLOW:       return "ALLOW";
        case PolicyAction::DENY:        return "DENY";
        case PolicyAction::FLAG:        return "FLAG";
        case PolicyAction::REQUIRE_MFA: return "REQUIRE_MFA";
        default:                        return "UNKNOWN";
    }
}

struct PolicyDecision {
    PolicyAction action = PolicyAction::DENY;
    std::string reason;
    std::string policy_id;
    
    // [E-8] Risk Multiplier: allows specific rules to "warp" the session faster
    float risk_weight = 1.0f; 
    
    std::string payload_hash;
    std::string matched_rule_id;
    
    // ZK proof for confidential evaluation
    std::optional<std::vector<uint8_t>> zk_proof;
    security::ZkProofType proof_type = security::ZkProofType::RANGE_PROOF;
};

struct Policy {
    std::string policy_id;
    std::string version;
    std::map<std::string, std::string> metadata;

    std::string compute_hash() const;
};

} // namespace uml001