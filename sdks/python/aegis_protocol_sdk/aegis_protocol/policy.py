"""
aegis_protocol.policy
-------------
PolicyEngine — CompatibilityManifest, TrustCriteria, ScopeCriteria.
"""

import dataclasses
import enum
from typing import List, Optional

from aegis_protocol.classifier import SemanticScore
from aegis_protocol.passport import SemanticPassport

RECOVERED_AGENT_CONFIDENCE_FLOOR: float = 0.95


class PolicyAction(enum.Enum):
    ALLOW = "ALLOW"
    FLAG  = "FLAG"
    DENY  = "DENY"


def action_str(action: PolicyAction) -> str:
    return action.value


class LogLevel(enum.Enum):
    DEBUG = "DEBUG"
    INFO  = "INFO"
    WARN  = "WARN"
    ALERT = "ALERT"


@dataclasses.dataclass
class TrustCriteria:
    min_authority_confidence:   float = 0.7
    min_sensitivity_confidence: float = 0.7


@dataclasses.dataclass
class ScopeCriteria:
    authority_min:   Optional[float] = None  # inclusive lower bound
    authority_max:   Optional[float] = None  # exclusive upper bound
    sensitivity_min: Optional[float] = None
    sensitivity_max: Optional[float] = None

    def matches(self, score: SemanticScore) -> bool:
        if self.authority_min is not None and score.authority < self.authority_min:
            return False
        if self.authority_max is not None and score.authority >= self.authority_max:
            return False
        if self.sensitivity_min is not None and score.sensitivity < self.sensitivity_min:
            return False
        if self.sensitivity_max is not None and score.sensitivity >= self.sensitivity_max:
            return False
        return True


@dataclasses.dataclass
class PolicyRule:
    rule_id:     str
    description: str
    trust:       TrustCriteria
    scope:       ScopeCriteria
    action:      PolicyAction
    log_level:   LogLevel = LogLevel.INFO


@dataclasses.dataclass
class CompatibilityManifest:
    expected_registry_version: str = ""
    policy_hash:               str = ""


@dataclasses.dataclass
class PolicyDecision:
    action:           PolicyAction
    matched_rule_id:  str = ""
    rejection_reason: str = ""
    log_level:        LogLevel = LogLevel.INFO


class PolicyEngine:
    """
    Evaluates a SemanticScore against an ordered list of PolicyRules.
    Falls back to *default_action* if no rule matches.
    """

    def __init__(
        self,
        manifest: CompatibilityManifest,
        rules: List[PolicyRule],
        default_action: PolicyAction = PolicyAction.DENY,
    ):
        self._manifest = manifest
        self._rules = rules
        self._default = default_action

    def evaluate(
        self,
        score: SemanticScore,
        registry_version: str,
        passport: Optional[SemanticPassport] = None,
    ) -> PolicyDecision:
        # Compatibility check
        if (self._manifest.expected_registry_version and
                registry_version != self._manifest.expected_registry_version):
            return PolicyDecision(
                action=PolicyAction.DENY,
                rejection_reason="COMPATIBILITY_MISMATCH",
                log_level=LogLevel.ALERT,
            )

        # Effective trust (elevated for recovered agents)
        base_trust = TrustCriteria()
        if passport is not None and passport.is_recovered():
            base_trust = TrustCriteria(
                min_authority_confidence=max(
                    base_trust.min_authority_confidence,
                    RECOVERED_AGENT_CONFIDENCE_FLOOR),
                min_sensitivity_confidence=max(
                    base_trust.min_sensitivity_confidence,
                    RECOVERED_AGENT_CONFIDENCE_FLOOR),
            )

        # Trust gate
        if (score.authority_confidence < base_trust.min_authority_confidence or
                score.sensitivity_confidence < base_trust.min_sensitivity_confidence):
            reason = (
                "TRUST_GATE_AUTHORITY"
                if score.authority_confidence < base_trust.min_authority_confidence
                else "TRUST_GATE_SENSITIVITY"
            )
            return PolicyDecision(
                action=PolicyAction.DENY,
                rejection_reason=reason,
                log_level=LogLevel.WARN,
            )

        # Rule matching — first match wins
        for rule in self._rules:
            # Per-rule trust check
            if (score.authority_confidence < rule.trust.min_authority_confidence or
                    score.sensitivity_confidence < rule.trust.min_sensitivity_confidence):
                continue
            if rule.scope.matches(score):
                return PolicyDecision(
                    action=rule.action,
                    matched_rule_id=rule.rule_id,
                    log_level=rule.log_level,
                )

        return PolicyDecision(action=self._default, rejection_reason="NO_RULE_MATCH")
