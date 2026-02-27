#pragma once
#include "classifier.h"
#include <vector>
#include <string>
#include <optional>
#include <iostream>
#include <cmath>
#include <stdexcept>

namespace uml001 {

enum class PolicyAction { ALLOW, DENY, FLAG };

inline std::string action_str(PolicyAction a) {
    switch (a) {
        case PolicyAction::ALLOW: return "ALLOW";
        case PolicyAction::DENY:  return "DENY";
        case PolicyAction::FLAG:  return "FLAG";
    }
    return "UNKNOWN";
}

enum class LogLevel { INFO, WARN, ALERT };

// ---------------------------------------------------------------------------
// 1. Policy Compatibility (Versioning & Environment Match)
// Ensures the policy being evaluated matches the active registry and protocol.
// ---------------------------------------------------------------------------
struct CompatibilityManifest {
    std::string expected_registry_version;
    std::string expected_protocol = "UML-001";
    std::string policy_hash;
};

// ---------------------------------------------------------------------------
// 2. Trustworthiness (Confidence & Integrity)
// Evaluates the reliability of the SemanticScore itself.
// ---------------------------------------------------------------------------
struct TrustCriteria {
    float min_authority_confidence = 0.8f; // Hardened from 0.5f
    float min_sensitivity_confidence = 0.8f;
    
    [[nodiscard]] bool is_trusted(const SemanticScore& score) const {
        // Guard against NaN injection bypasses
        if (std::isnan(score.authority_confidence) || std::isnan(score.sensitivity_confidence)) {
            return false;
        }
        return score.authority_confidence >= min_authority_confidence &&
               score.sensitivity_confidence >= min_sensitivity_confidence;
    }
};

// ---------------------------------------------------------------------------
// 3. Privilege Scope (Authority & Sensitivity Bounds)
// Defines the operational boundaries for a given rule.
// ---------------------------------------------------------------------------
struct ScopeCriteria {
    std::optional<float> authority_min;
    std::optional<float> authority_max;
    std::optional<float> sensitivity_min;
    std::optional<float> sensitivity_max;

    [[nodiscard]] bool is_within_scope(const SemanticScore& score) const {
        if (std::isnan(score.authority) || std::isnan(score.sensitivity)) return false;

        if (authority_min.has_value() && score.authority < authority_min.value()) return false;
        if (authority_max.has_value() && score.authority > authority_max.value()) return false;
        if (sensitivity_min.has_value() && score.sensitivity < sensitivity_min.value()) return false;
        if (sensitivity_max.has_value() && score.sensitivity > sensitivity_max.value()) return false;

        return true;
    }
};

// ---------------------------------------------------------------------------
// Composed Policy Rule
// ---------------------------------------------------------------------------
struct PolicyRule {
    std::string   rule_id;
    std::string   description;
    TrustCriteria trust;
    ScopeCriteria scope;
    PolicyAction  action    = PolicyAction::DENY; // Fail-safe default
    LogLevel      log_level = LogLevel::INFO;
};

struct PolicyDecision {
    PolicyAction action;
    std::string  matched_rule_id;
    LogLevel     log_level;
    std::string  payload_hash;
    std::string  rejection_reason; // Added for better auditability
};

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------
class PolicyEngine {
public:
    // Notice default_action is now DENY
    explicit PolicyEngine(CompatibilityManifest manifest,
                          std::vector<PolicyRule> rules,
                          PolicyAction default_action = PolicyAction::DENY)
        : manifest_(std::move(manifest))
        , rules_(std::move(rules))
        , default_action_(default_action) {}

    [[nodiscard]] PolicyDecision evaluate(const SemanticScore& score, const std::string& active_registry) const {
        PolicyDecision decision;
        decision.payload_hash = score.payload_hash;
        
        // Phase 1: Compatibility Check
        if (active_registry != manifest_.expected_registry_version) {
            decision.action = PolicyAction::DENY;
            decision.log_level = LogLevel::ALERT;
            decision.rejection_reason = "COMPATIBILITY_MISMATCH";
            return decision;
        }

        // Phase 2: Rule Evaluation
        for (const auto& rule : rules_) {
            // Check Trustworthiness first
            if (!rule.trust.is_trusted(score)) {
                continue; // Skip to next rule, or you could immediately flag it
            }

            // Check Privilege Scope
            if (rule.scope.is_within_scope(score)) {
                decision.action          = rule.action;
                decision.matched_rule_id = rule.rule_id;
                decision.log_level       = rule.log_level;
                return decision;
            }
        }

        // Phase 3: Fallback to Fail-Safe Default
        decision.action           = default_action_;
        decision.log_level        = (default_action_ == PolicyAction::DENY) ? LogLevel::WARN : LogLevel::INFO;
        decision.rejection_reason = "NO_MATCHING_RULE_DEFAULT_DENY";
        return decision;
    }

    [[nodiscard]] bool permits(const SemanticScore& score, const std::string& active_registry) const {
        return evaluate(score, active_registry).action != PolicyAction::DENY;
    }

private:
    CompatibilityManifest   manifest_;
    std::vector<PolicyRule> rules_;
    PolicyAction            default_action_;
};

} // namespace uml001