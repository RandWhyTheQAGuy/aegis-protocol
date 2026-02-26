// policy.h
    #pragma once
    #include "classifier.h"
    #include <vector>
    #include <string>
    #include <optional>
    #include <iostream>

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

    inline std::string loglevel_str(LogLevel l) {
        switch (l) {
            case LogLevel::INFO:  return "INFO";
            case LogLevel::WARN:  return "WARN";
            case LogLevel::ALERT: return "ALERT";
        }
        return "INFO";
    }

    struct PolicyRule {
        std::string              rule_id;
        std::string              description;
        std::optional<float>     authority_below;
        std::optional<float>     authority_above;
        std::optional<float>     sensitivity_above;
        std::optional<float>     sensitivity_below;
        float                    min_confidence = 0.5f;
        PolicyAction             action         = PolicyAction::ALLOW;
        LogLevel                 log_level      = LogLevel::INFO;
    };

    struct PolicyDecision {
        PolicyAction action;
        std::string  matched_rule_id;   // empty if default applied
        LogLevel     log_level;
        bool         low_confidence;
        std::string  payload_hash;
    };

    // ---------------------------------------------------------------------------
    // PolicyEngine: evaluates a SemanticScore against an ordered rule list
    // ---------------------------------------------------------------------------
    class PolicyEngine {
    public:
        explicit PolicyEngine(std::vector<PolicyRule> rules,
                              PolicyAction default_action = PolicyAction::ALLOW)
            : rules_(std::move(rules))
            , default_action_(default_action) {}

        PolicyDecision evaluate(const SemanticScore& score) const {
            PolicyDecision decision;
            decision.payload_hash    = score.payload_hash;
            decision.low_confidence  = score.is_low_confidence();

            float min_conf = std::min(score.authority_confidence,
                                      score.sensitivity_confidence);

            for (const auto& rule : rules_) {
                // Skip rule if score confidence is below rule's threshold
                if (min_conf < rule.min_confidence) continue;

                bool match = true;

                if (rule.authority_below.has_value() &&
                    !(score.authority < rule.authority_below.value()))
                    match = false;

                if (match && rule.authority_above.has_value() &&
                    !(score.authority > rule.authority_above.value()))
                    match = false;

                if (match && rule.sensitivity_above.has_value() &&
                    !(score.sensitivity > rule.sensitivity_above.value()))
                    match = false;

                if (match && rule.sensitivity_below.has_value() &&
                    !(score.sensitivity < rule.sensitivity_below.value()))
                    match = false;

                if (match) {
                    decision.action          = rule.action;
                    decision.matched_rule_id = rule.rule_id;
                    decision.log_level       = rule.log_level;
                    return decision;
                }
            }

            // No rule matched: apply default
            decision.action    = default_action_;
            decision.log_level = LogLevel::INFO;
            return decision;
        }

        // Convenience: returns true iff action is ALLOW or FLAG
        bool permits(const SemanticScore& score) const {
            return evaluate(score).action != PolicyAction::DENY;
        }

    private:
        std::vector<PolicyRule> rules_;
        PolicyAction            default_action_;
    };

    } // namespace uml001
