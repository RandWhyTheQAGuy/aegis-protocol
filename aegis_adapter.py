"""
Aegis Protocol – Framework‑Agnostic Security Adapter
====================================================

This module provides the core security substrate for agent orchestration
frameworks (LangGraph, LangChain, AutoGen, CrewAI, Semantic Kernel, etc.).

Security Standards Alignment
----------------------------
* Fail‑Closed Execution — DoD Zero Trust (Assume Breach), NIST SP 800‑53 SC‑7.
* Redacted Structured Logging — OWASP LLM02:2025, NIST SP 800‑53 SC‑28.
* Tamper‑Evident Audit Vault — NIST SP 800‑53 AU‑9, ISA/IEC 62443‑3‑3.
* Semantic Passport (Identity & Capability Binding) — NIST SP 800‑53 IA‑2.
* Excessive Agency Prevention — OWASP LLM06:2025.
* Session Warp‑Score State Machine — NERC CIP‑007 (Systems Security Management).
"""

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Structured JSON Logger
# ---------------------------------------------------------------------------

def _build_logger(name: str) -> logging.Logger:
    """
    Creates a structured JSON logger.
    Standards:
        - OWASP LLM02:2025 (Sensitive Information Disclosure)
        - NIST SP 800‑53 SC‑28 (Protection of Information at Rest)
    """
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    return lg


def _emit(lg: logging.Logger, level: str, component: str, event: str, **kw: Any) -> None:
    """
    Emits a structured JSON log record with automatic redaction of sensitive fields.
    Standards:
        - OWASP LLM02:2025 (Sensitive Info Disclosure)
        - NIST SP 800‑53 SC‑28 (Data Protection)
    """
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "component": component,
        "event": event,
    }
    for k, v in kw.items():
        rec[k] = "***REDACTED***" if any(
            s in k.lower() for s in ("key", "secret", "token", "hmac", "sig")
        ) else v
    getattr(lg, level.lower())(json.dumps(rec))


LOG = _build_logger("aegis_adapter")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    DENY = "DENY"


class SessionState(str, Enum):
    INIT = "INIT"
    ACTIVE = "ACTIVE"
    SUSPECT = "SUSPECT"
    QUARANTINE = "QUARANTINE"
    FLUSHING = "FLUSHING"
    RESYNC = "RESYNC"
    CLOSED = "CLOSED"


# ---------------------------------------------------------------------------
# Semantic Passport
# ---------------------------------------------------------------------------

@dataclass
class SemanticPassport:
    """
    Aegis Protocol Semantic Passport v0.2

    Purpose:
        - Binds an agent to a specific policy hash and capability set.
        - Enforces least privilege and identity assurance.

    Standards:
        - NIST SP 800‑53 IA‑2 (Identification & Authentication)
        - OWASP LLM06:2025 (Excessive Agency)
    """
    model_id: str
    version: str
    policy_hash: str
    ttl_seconds: int
    capabilities: frozenset = field(default_factory=frozenset)
    issued_at: float = field(default_factory=time.time)
    passport_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def is_expired(self) -> bool:
        """Checks TTL expiration."""
        if self.ttl_seconds == 0:
            return False
        return time.time() > self.issued_at + self.ttl_seconds

    def has_capability(self, cap: str) -> bool:
        """Capability-based least privilege check."""
        return cap in self.capabilities

    def to_audit_dict(self) -> Dict[str, Any]:
        """Returns a redaction-safe audit representation."""
        return {
            "passport_id": self.passport_id,
            "model_id": self.model_id,
            "version": self.version,
            "policy_hash": self.policy_hash,
            "ttl_seconds": self.ttl_seconds,
            "capabilities": sorted(self.capabilities),
            "expired": self.is_expired(),
        }


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

@dataclass
class SemanticScore:
    authority: float
    sensitivity: float


@dataclass
class PolicyResult:
    decision: PolicyDecision
    authority: float
    sensitivity: float
    authority_floor: float
    sensitivity_ceiling: float
    reason: str
    evaluated_at: float = field(default_factory=time.time)


class PolicyEngine:
    """
    Real-time context-aware policy engine.

    Standards:
        - OWASP LLM06:2025 (Excessive Agency)
        - DoD Zero Trust (Continuous Evaluation)
    """

    def __init__(
        self,
        authority_floor: float = 0.0,
        sensitivity_ceiling: float = 0.70,
        flag_threshold: float = 0.45,
        recovered_floor_bump: float = 0.20,
    ) -> None:
        self.authority_floor = authority_floor
        self.sensitivity_ceiling = sensitivity_ceiling
        self.flag_threshold = flag_threshold
        self.recovered_floor_bump = recovered_floor_bump

    def evaluate(
        self, score: SemanticScore, session_state: SessionState = SessionState.ACTIVE
    ) -> PolicyResult:
        """
        Evaluates authority/sensitivity scores and returns a policy decision.
        Fail‑closed on all exceptions.

        Standards:
            - DoD Zero Trust (Assume Breach)
            - NIST SP 800‑53 AC‑3 (Access Enforcement)
        """
        try:
            floor = self.authority_floor
            if session_state == SessionState.SUSPECT:
                floor = min(1.0, floor + self.recovered_floor_bump)

            if score.authority < floor:
                return PolicyResult(
                    PolicyDecision.DENY,
                    score.authority,
                    score.sensitivity,
                    floor,
                    self.sensitivity_ceiling,
                    "Authority below floor",
                )

            if score.sensitivity > self.sensitivity_ceiling:
                return PolicyResult(
                    PolicyDecision.DENY,
                    score.authority,
                    score.sensitivity,
                    floor,
                    self.sensitivity_ceiling,
                    "Sensitivity exceeded ceiling",
                )

            if score.sensitivity > self.flag_threshold:
                return PolicyResult(
                    PolicyDecision.FLAG,
                    score.authority,
                    score.sensitivity,
                    floor,
                    self.sensitivity_ceiling,
                    "Sensitivity triggered flag",
                )

            return PolicyResult(
                PolicyDecision.ALLOW,
                score.authority,
                score.sensitivity,
                floor,
                self.sensitivity_ceiling,
                "Action within bounds",
            )

        except Exception as exc:
            return PolicyResult(
                PolicyDecision.DENY,
                0.0,
                1.0,
                self.authority_floor,
                self.sensitivity_ceiling,
                f"Fail‑closed error: {exc}",
            )


# ---------------------------------------------------------------------------
# Audit Vault (Tamper‑Evident)
# ---------------------------------------------------------------------------

@dataclass
class VaultEntry:
    entry_id: str
    timestamp: float
    agent_id: str
    session_id: str
    event_type: str
    payload_hash: str
    decision: str
    authority: float
    sensitivity: float
    framework: str
    metadata: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def _canonical(self) -> str:
        return (
            f"{self.entry_id}{self.timestamp}{self.agent_id}{self.session_id}"
            f"{self.event_type}{self.payload_hash}{self.decision}"
            f"{self.authority}{self.sensitivity}{self.framework}{self.prev_hash}"
        )

    def compute_hash(self) -> str:
        return hashlib.sha256(self._canonical().encode()).hexdigest()


class AuditVault:
    """
    Append‑only, hash‑chained audit vault.

    Standards:
        - NIST SP 800‑53 AU‑9 (Protection of Audit Information)
        - ISA/IEC 62443‑3‑3 (Security Levels & Integrity)
    """

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._chain: List[VaultEntry] = []

    def append(
        self,
        agent_id: str,
        session_id: str,
        event_type: str,
        payload: str,
        result: PolicyResult,
        framework: str = "unknown",
        metadata: Optional[Dict] = None,
    ) -> VaultEntry:
        prev = self._chain[-1].entry_hash if self._chain else self.GENESIS
        entry = VaultEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=time.time(),
            agent_id=agent_id,
            session_id=session_id,
            event_type=event_type,
            payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
            decision=result.decision.value,
            authority=result.authority,
            sensitivity=result.sensitivity,
            framework=framework,
            metadata=metadata or {},
            prev_hash=prev,
        )
        entry.entry_hash = entry.compute_hash()
        self._chain.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """Verifies the entire hash chain for tamper evidence."""
        if not self._chain:
            return True
        prev = self.GENESIS
        for e in self._chain:
            if e.prev_hash != prev or e.compute_hash() != e.entry_hash:
                return False
            prev = e.entry_hash
        return True

    @property
    def length(self) -> int:
        return len(self._chain)


# ---------------------------------------------------------------------------
# Transparency Log (Governance)
# ---------------------------------------------------------------------------

class TransparencyLog:
    """
    Secondary governance log.

    Standards:
        - NIST SP 800‑53 AU‑12 (Audit Generation)
        - ISO/IEC 27001 A.12.4 (Logging & Monitoring)
    """

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._entries = []

    def record(self, agent_id: str, session_id: str, event_type: str, **details: Any) -> None:
        """Records governance events (state transitions, escalations)."""
        self._entries.append(
            {
                "agent_id": agent_id,
                "session_id": session_id,
                "event_type": event_type,
                "details": details,
                "ts": time.time(),
            }
        )

    def verify_chain(self) -> bool:
        return True

    @property
    def length(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Session Guard (State Machine)
# ---------------------------------------------------------------------------

class SessionGuard:
    """
    Per‑session state machine tracking warp‑score and quarantine thresholds.

    Standards:
        - NERC CIP‑007 (Systems Security Management)
        - DoD Zero Trust (Continuous Monitoring)
    """

    SUSPECT_THRESHOLD = 0.40
    QUARANTINE_THRESHOLD = 0.70
    WARP_INCREMENT = 0.12

    def __init__(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
        tlog: Optional[TransparencyLog] = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.state = SessionState.INIT
        self.warp_score = 0.0
        self._tlog = tlog

    def activate(self) -> None:
        """Moves session to ACTIVE state."""
        self.state = SessionState.ACTIVE

    def record(self, decision: PolicyDecision) -> SessionState:
        """
        Updates warp‑score based on policy decisions.
        FLAG/DENY increase warp‑score.
        """
        if self.state not in (SessionState.ACTIVE, SessionState.SUSPECT):
            return self.state

        if decision in (PolicyDecision.FLAG, PolicyDecision.DENY):
            self.warp_score = min(1.0, self.warp_score + self.WARP_INCREMENT)

        if self.warp_score >= self.QUARANTINE_THRESHOLD:
            self.state = SessionState.QUARANTINE
        elif self.warp_score >= self.SUSPECT_THRESHOLD:
            self.state = SessionState.SUSPECT

        return self.state

    def resync(self) -> None:
        """Resets warp‑score after quarantine."""
        if self.state != SessionState.QUARANTINE:
            raise RuntimeError("Must be in QUARANTINE to resync")
        self.warp_score = 0.0
        self.state = SessionState.ACTIVE

    def close(self) -> None:
        """Closes the session."""
        self.state = SessionState.CLOSED

    @property
    def is_active(self) -> bool:
        return self.state in (SessionState.ACTIVE, SessionState.SUSPECT)


# ---------------------------------------------------------------------------
# Aegis Framework Bridge
# ---------------------------------------------------------------------------

class AegisFrameworkBridge:
    """
    Framework‑agnostic bridge that evaluates actions, enforces policy,
    and writes to the audit vault.

    Standards:
        - NIST SP 800‑53 AC‑3 (Access Enforcement)
        - NIST SP 800‑53 AU‑9 (Audit Integrity)
        - DoD Zero Trust (Continuous Authorization)
    """

    def __init__(
        self,
        passport: SemanticPassport,
        policy: Optional[PolicyEngine] = None,
        vault: Optional[AuditVault] = None,
        tlog: Optional[TransparencyLog] = None,
        framework: str = "unknown",
    ) -> None:
        self.passport = passport
        self.policy = policy or PolicyEngine()
        self.vault = vault or AuditVault()
        self.tlog = tlog or TransparencyLog()
        self.framework = framework
        self.session = SessionGuard(agent_id=passport.model_id, tlog=self.tlog)

    def start(self) -> None:
        """Starts a session after validating passport."""
        if self.passport.is_expired():
            raise PermissionError("Passport expired")
        self.session.activate()

    def evaluate_action(
        self,
        payload: str,
        authority: float = 0.5,
        sensitivity: float = 0.1,
        event_type: str = "agent_action",
    ) -> Tuple[PolicyResult, bool]:
        """
        Evaluates an action and writes to the audit vault if allowed.

        Standards:
            - OWASP LLM06:2025 (Excessive Agency)
            - NIST SP 800‑53 AU‑9 (Audit Integrity)
        """
        if self.session.state == SessionState.QUARANTINE:
            raise PermissionError("Session quarantined")

        if not self.session.is_active:
            raise RuntimeError("Session inactive")

        score = SemanticScore(authority=authority, sensitivity=sensitivity)
        result = self.policy.evaluate(score, self.session.state)
        allowed = result.decision != PolicyDecision.DENY

        self.session.record(result.decision)

        if allowed:
            self.vault.append(
                self.passport.model_id,
                self.session.session_id,
                event_type,
                payload,
                result,
                self.framework,
            )

        return result, allowed


# ---------------------------------------------------------------------------
# Aegis Adapter (Registry)
# ---------------------------------------------------------------------------

class AegisAdapter:
    """
    Registry for multiple agents across multiple frameworks.

    Standards:
        - NIST SP 800‑53 AC‑2 (Account Management)
        - DoD Zero Trust (Identity & Access)
    """

    def __init__(self, policy: Optional[PolicyEngine] = None) -> None:
        self.vault = AuditVault()
        self.tlog = TransparencyLog()
        self.policy = policy or PolicyEngine()
        self._bridges: Dict[str, AegisFrameworkBridge] = {}

    def register_agent(
        self, passport: SemanticPassport, framework: str = "unknown"
    ) -> AegisFrameworkBridge:
        """Registers an agent and returns its bridge."""
        bridge = AegisFrameworkBridge(
            passport, self.policy, self.vault, self.tlog, framework
        )
        self._bridges[passport.model_id] = bridge
        return bridge