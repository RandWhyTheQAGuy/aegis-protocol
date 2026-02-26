"""
aegis.policy
~~~~~~~~~~~~
PolicyRule, PolicyDecision, and PolicyEngine.

The Policy Engine evaluates every message payload against an ordered list of
rules before it is processed. It is the primary enforcement point for semantic
access control in a UML-001 agent cluster.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .classifier import SemanticScore
from .exceptions import PolicyRuleValidationError


class PolicyAction(Enum):
    """Outcome of a policy evaluation."""

    ALLOW = "ALLOW"
    """Payload proceeds. Logged at INFO."""

    DENY = "DENY"
    """Payload rejected. Session Warp Score incremented. Logged at ALERT."""

    FLAG = "FLAG"
    """Payload proceeds with a FLAG annotation. Logged at WARN.
    Receiving agents SHOULD propagate the flag to downstream outputs."""


class LogLevel(Enum):
    """Log severity for a policy decision."""
    INFO  = "INFO"
    WARN  = "WARN"
    ALERT = "ALERT"


@dataclass
class PolicyRule:
    """A single rule in an ordered policy rule set.

    Conditions are ANDed: all non-None conditions must match for the rule
    to fire. Rules are evaluated in list order; first match wins.

    Fields correspond 1:1 with ``spec/schemas/policy-rule.schema.json``.

    Attributes:
        rule_id:           Unique rule identifier (alphanumeric + hyphens).
        action:            Action to take on match.
        description:       Human-readable intent.
        authority_below:   Match if authority < this value.
        authority_above:   Match if authority > this value.
        sensitivity_above: Match if sensitivity > this value.
        sensitivity_below: Match if sensitivity < this value.
        min_confidence:    Skip rule if either confidence is below this.
        log_level:         Severity of log entry on match.
    """

    rule_id: str
    action: PolicyAction
    description: str = ""
    authority_below: Optional[float] = None
    authority_above: Optional[float] = None
    sensitivity_above: Optional[float] = None
    sensitivity_below: Optional[float] = None
    min_confidence: float = 0.5
    log_level: LogLevel = LogLevel.INFO

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.replace("-", "").replace("_", "").isalnum():
            raise PolicyRuleValidationError(
                f"rule_id must be non-empty alphanumeric+hyphens: {self.rule_id!r}"
            )
        if not (0.0 <= self.min_confidence <= 1.0):
            raise PolicyRuleValidationError(
                f"min_confidence must be in [0.0, 1.0]: {self.min_confidence}"
            )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "authority_below": self.authority_below,
            "authority_above": self.authority_above,
            "sensitivity_above": self.sensitivity_above,
            "sensitivity_below": self.sensitivity_below,
            "min_confidence": self.min_confidence,
            "action": self.action.value,
            "log_level": self.log_level.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyRule":
        return cls(
            rule_id=data["rule_id"],
            action=PolicyAction(data["action"]),
            description=data.get("description", ""),
            authority_below=data.get("authority_below"),
            authority_above=data.get("authority_above"),
            sensitivity_above=data.get("sensitivity_above"),
            sensitivity_below=data.get("sensitivity_below"),
            min_confidence=data.get("min_confidence", 0.5),
            log_level=LogLevel(data.get("log_level", "INFO")),
        )


@dataclass
class PolicyDecision:
    """The result of evaluating a :class:`SemanticScore` against a rule set.

    Attributes:
        action:          Outcome of evaluation.
        payload_hash:    Hash of the evaluated payload.
        matched_rule_id: ID of the rule that matched, or '' if default applied.
        log_level:       Severity for logging.
        low_confidence:  True if either classifier confidence was below threshold.
    """

    action: PolicyAction
    payload_hash: str
    matched_rule_id: str = ""
    log_level: LogLevel = LogLevel.INFO
    low_confidence: bool = False

    def is_permitted(self) -> bool:
        """Return True if the payload should be processed (ALLOW or FLAG)."""
        return self.action != PolicyAction.DENY

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "payload_hash": self.payload_hash,
            "matched_rule_id": self.matched_rule_id,
            "log_level": self.log_level.value,
            "low_confidence": self.low_confidence,
        }


# ---------------------------------------------------------------------------
# Default rule set (mirrors UML-001 spec defaults)
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[PolicyRule] = [
    PolicyRule(
        rule_id="deny-low-auth-high-sens",
        description="Deny low-authority agents accessing high-sensitivity content",
        authority_below=-0.5,
        sensitivity_above=0.8,
        min_confidence=0.5,
        action=PolicyAction.DENY,
        log_level=LogLevel.ALERT,
    ),

]


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Evaluates SemanticScores against an ordered list of PolicyRules.

    Rules are evaluated in order; the first matching rule determines the
    outcome. If no rule matches, ``default_action`` applies (default: ALLOW).

    Args:
        rules:          Ordered list of :class:`PolicyRule` objects.
        default_action: Action when no rule matches. Default ALLOW.

    Example::

        engine = PolicyEngine.from_defaults()
        score  = classifier.score("Please summarize the report.")
        decision = engine.evaluate(score)
        if not decision.is_permitted():
            raise PolicyDenyError(decision.matched_rule_id, score.payload_hash)

    Loading from a JSON file::

        import json
        with open("policy_rules.json") as f:
            rules = [PolicyRule.from_dict(r) for r in json.load(f)]
        engine = PolicyEngine(rules)
    """

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        default_action: PolicyAction = PolicyAction.ALLOW,
        flag_low_confidence: bool = True,
    ) -> None:
        self._rules = list(rules or [])
        self._default = default_action
        self._flag_low_confidence = flag_low_confidence

    @classmethod
    def from_defaults(cls) -> "PolicyEngine":
        """Return a PolicyEngine loaded with the default UML-001 rule set."""
        return cls(rules=list(DEFAULT_RULES), flag_low_confidence=True)

    @classmethod
    def from_dict_list(cls, data: List[dict]) -> "PolicyEngine":
        """Construct from a list of rule dicts (e.g., loaded from JSON)."""
        return cls(rules=[PolicyRule.from_dict(r) for r in data])

    def evaluate(self, score: SemanticScore) -> PolicyDecision:
        """Evaluate *score* and return a :class:`PolicyDecision`.

        Args:
            score: The :class:`SemanticScore` to evaluate.

        Returns:
            A :class:`PolicyDecision` describing the outcome.
        """
        min_conf = min(score.authority_confidence, score.sensitivity_confidence)
        low_confidence = score.is_low_confidence()

        for rule in self._rules:
            # Skip rule if score confidence is below rule's threshold
            if min_conf < rule.min_confidence:
                continue

            if not self._matches(rule, score):
                continue

            return PolicyDecision(
                action=rule.action,
                payload_hash=score.payload_hash,
                matched_rule_id=rule.rule_id,
                log_level=rule.log_level,
                low_confidence=low_confidence,
            )

        # No rule matched: auto-FLAG low-confidence payloads before default
        if low_confidence and self._flag_low_confidence:
            return PolicyDecision(
                action=PolicyAction.FLAG,
                payload_hash=score.payload_hash,
                matched_rule_id="flag-low-confidence",
                log_level=LogLevel.WARN,
                low_confidence=True,
            )

        # Default action
        return PolicyDecision(
            action=self._default,
            payload_hash=score.payload_hash,
            matched_rule_id="",
            log_level=LogLevel.INFO,
            low_confidence=low_confidence,
        )

    def permits(self, score: SemanticScore) -> bool:
        """Convenience method. Return True iff action is ALLOW or FLAG."""
        return self.evaluate(score).is_permitted()

    @staticmethod
    def _matches(rule: PolicyRule, score: SemanticScore) -> bool:
        """Return True if all non-None conditions in *rule* match *score*."""
        if rule.authority_below is not None and score.authority >= rule.authority_below:
            return False
        if rule.authority_above is not None and score.authority <= rule.authority_above:
            return False
        if rule.sensitivity_above is not None and score.sensitivity <= rule.sensitivity_above:
            return False
        if rule.sensitivity_below is not None and score.sensitivity >= rule.sensitivity_below:
            return False
        return True

    def __repr__(self) -> str:
        return f"PolicyEngine(rules={len(self._rules)}, default={self._default.value})"
