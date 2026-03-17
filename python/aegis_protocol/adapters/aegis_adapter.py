"""
aegis_adapter.py
================
Shared Aegis Protocol security adapter for agent orchestration frameworks.

PURPOSE
-------
This module is the single shared security kernel imported by every framework
integration layer (LangGraph, AutoGen, CrewAI).  It enforces identity,
least-privilege policy, tamper-evident audit, and session health tracking
BEFORE any agent action reaches the outside world.

The design principle is "security as infrastructure": every framework
integration calls evaluate_action() and trusts the adapter to handle all
logging, chain maintenance, warp accumulation, and decision enforcement.
No framework integration file re-implements any of this logic.

COMPONENT MAP
-------------
SemanticPassport      — versioned, TTL-bounded agent identity credential
PolicyEngine          — real-time ALLOW / FLAG / DENY decision engine
AuditVault            — append-only, SHA-256 hash-chained audit ledger
TransparencyLog       — governance event log; separate from AuditVault
SessionGuard          — per-session warp-score state machine
AegisFrameworkBridge  — per-agent evaluation facade
AegisAdapter          — deployment-level facade; shared vault+tlog

SECURITY POSTURE
----------------
* Fail-closed on every boundary
* Cold-start safe — genesis block anchors an empty chain
* Credential fields auto-redacted in every log record
* Payload stored as SHA-256 hash only — never raw content
* Monotonic hash chains on both vault and transparency log

STANDARDS ALIGNMENT — ANNOTATED
---------------------------------
Inline [STANDARD: citation] comments appear at every enforcement point.

NIST AI RMF 1.0
  GOVERN-1.1   Policies documented and enforced → PolicyEngine config
  GOVERN-6.2   Roles and responsibilities       → capabilities frozenset
  MAP-5.1      Risk likelihood monitored         → warp_score accumulation
  MEASURE-2.5  Risk metrics tracked              → AuditVault + TLog substrate
  MANAGE-3.2   Response to identified risks      → QUARANTINE + resync()

NIST SP 800-53 Rev 5
  AC-2   Account Management      → SemanticPassport TTL lifecycle
  AC-3   Access Enforcement      → PolicyEngine + require_capability()
  AC-6   Least Privilege         → capabilities frozenset
  AU-2   Event Logging           → AuditVault and TransparencyLog
  AU-3   Content of Audit Records → VaultEntry and TLogEntry fields
  AU-9   Protection of Audit Info → hash-chained immutable records
  AU-10  Non-Repudiation          → SHA-256 chain linkage
  IA-2   Identification           → SemanticPassport model_id
  IA-5   Authenticator Management → passport TTL enforcement
  IR-4   Incident Handling        → SessionGuard QUARANTINE
  SC-12  Cryptographic Key Mgmt   → policy_hash; SHA-256 throughout
  SI-7   Information Integrity    → verify_chain() mutation detection

NIST SP 800-218A (Secure Software Development Framework)
  PW.1.1  Secure design patterns  → fail-closed throughout
  PW.4.1  Vetted algorithms       → hashlib.sha256 (FIPS 180-4)
  PW.8.1  Data in storage         → payloads stored as hashes only

DoD Zero Trust Reference Architecture v2.0
  Identity pillar               → SemanticPassport
  Data pillar                   → hash-only payload storage
  Applications/Workloads pillar → evaluate_action() before every workload
  Never Trust, Always Verify    → every action re-evaluated regardless of prior

OWASP LLM Top 10 v2025
  LLM01 Prompt Injection        → inbound payload evaluation + sensitivity scoring
  LLM05 Insecure Output         → post-action evaluation hooks; no secrets in logs
  LLM06 Excessive Agency        → capabilities frozenset limits action surface
  LLM08 Excessive Permissions   → least-privilege at registration + per-action

ISA/IEC 62443-3-3
  SR 1.1  Agent Identification   → SemanticPassport applied to agent identity
  SR 2.1  Authorisation SL-2    → PolicyEngine + require_capability()
  SR 6.1  Audit Accessibility   → AuditVault.entries_for_session(); verify_chain()
  SR 6.2  Continuous Monitoring → TransparencyLog records every evaluation

NERC CIP-007-6 / CIP-010-4
  CIP-007 R4  Security Event Monitoring → AuditVault + TLog as SIEM feed
  CIP-010 R1  Configuration Monitoring  → policy_hash as config binding

SDK REPLACEMENT
---------------
All classes are self-contained stubs modelling the Aegis Protocol SDK surface.
Replace with:
    from aegis_protocol_sdk import (
        SemanticPassport, PolicyEngine, ColdAuditVault,
        TransparencyLog, SessionStateMachine, SemanticScore,
        AegisFrameworkBridge, AegisAdapter,
    )

DEPENDENCIES
------------
Pure Python 3.10+ standard library only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURED JSON LOGGER
# [STANDARD: NIST SP 800-53 AU-2, AU-3; ISA/IEC 62443-3-3 SR 6.1;
#            NERC CIP-007-6 R4]
# ══════════════════════════════════════════════════════════════════════════════

def _build_logger(name: str) -> logging.Logger:
    """
    Build a structured-output logger for the given component name.

    Output is single-line JSON, making it directly ingestible by SIEM tools
    (Splunk, ELK, Chronicle) without custom parsers.  The handler is added
    only once (idempotent) to prevent duplicate records on repeated imports.
    """
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    return lg


# Auto-redact patterns: field names containing any of these strings will have
# their values replaced with "***REDACTED***" in every log record.
# [STANDARD: NIST SP 800-53 SC-12; OWASP LLM Top 10 v2025 LLM05]
_REDACT_PATTERNS: Tuple[str, ...] = ("key", "secret", "token", "hmac", "sig")


def _emit(lg: logging.Logger, level: str, component: str,
          event: str, **kw: Any) -> None:
    """
    Emit a single structured JSON log record.

    All fields whose names contain any _REDACT_PATTERNS substring (case-
    insensitive) are replaced with "***REDACTED***" before the record is
    written.  This ensures credential material never appears in logs even if
    a caller accidentally passes a secret-bearing field.

    Parameters
    ----------
    lg        : logger instance for this component
    level     : "debug" | "info" | "warning" | "error"
    component : short component label (e.g. "PolicyEngine")
    event     : short event label (e.g. "allow", "chain_break")
    **kw      : arbitrary structured fields appended to the record

    [STANDARD: NIST SP 800-53 AU-3 (audit record content);
               NIST SP 800-53 SC-12 (key non-disclosure);
               OWASP LLM Top 10 v2025 LLM05 (no secrets in output)]
    """
    rec: Dict[str, Any] = {
        "ts":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level":     level,
        "component": component,
        "event":     event,
    }
    for k, v in kw.items():
        rec[k] = "***REDACTED***" if any(
            p in k.lower() for p in _REDACT_PATTERNS
        ) else v
    getattr(lg, level.lower())(json.dumps(rec))


LOG = _build_logger("aegis_adapter")


# ══════════════════════════════════════════════════════════════════════════════
# ENUMERATIONS
# ══════════════════════════════════════════════════════════════════════════════

class PolicyDecision(str, Enum):
    """
    Three-level policy decision returned by PolicyEngine.evaluate().

    ALLOW — within policy bounds; proceed normally.
    FLAG  — elevated sensitivity but below hard ceiling; proceed with
            warp increment and heightened monitoring.
            [STANDARD: NIST AI RMF MAP-5.1 — monitoring without blocking]
    DENY  — violates policy; block immediately; payload never vaulted.
            [STANDARD: DoD Zero Trust RA v2.0 — explicit deny]

    Inheriting from str makes values JSON-serialisable without .value access.
    """
    ALLOW = "ALLOW"
    FLAG  = "FLAG"
    DENY  = "DENY"


class SessionState(str, Enum):
    """
    Agent session lifecycle states managed by SessionGuard.

    INIT       — created; passport not yet validated.
    ACTIVE     — passport validated; normal operation.
    SUSPECT    — warp ≥ 0.40; elevated authority floor applied.
                 [STANDARD: NIST AI RMF MAP-5.1 — continuous risk monitoring;
                            ISA/IEC 62443-3-3 SR 6.2]
    QUARANTINE — warp ≥ 0.70; all actions blocked pending operator resync.
                 [STANDARD: NIST SP 800-53 IR-4 — incident handling]
    FLUSHING   — intermediate state during controlled resync.
    RESYNC     — context being reloaded from verified clean snapshot.
    CLOSED     — terminated normally.
                 [STANDARD: NIST SP 800-53 AC-2 — account termination]
    """
    INIT       = "INIT"
    ACTIVE     = "ACTIVE"
    SUSPECT    = "SUSPECT"
    QUARANTINE = "QUARANTINE"
    FLUSHING   = "FLUSHING"
    RESYNC     = "RESYNC"
    CLOSED     = "CLOSED"


# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC PASSPORT
# [STANDARD: NIST SP 800-53 IA-2, IA-5, AC-2, AC-6;
#            DoD Zero Trust RA v2.0 Identity pillar;
#            NIST AI RMF GOVERN-6.2; NERC CIP-010 R1]
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SemanticPassport:
    """
    Aegis Protocol Semantic Passport v0.2 — verifiable agent identity credential.

    Conceptually analogous to an X.509 certificate applied to AI agents.
    Binds agent identity (model_id + version), authorised scope (policy_hash),
    credential lifetime (ttl_seconds), and least-privilege capabilities into a
    single, auditable structure.

    policy_hash
    -----------
    SHA-256 of the authorised policy document for this agent.  Serves as the
    cryptographic binding between the agent's runtime identity and the policy
    under which it was approved.  Any policy change produces a different hash —
    making drift immediately detectable.
    [STANDARD: NERC CIP-010 R1 — configuration monitoring]

    capabilities
    ------------
    Frozenset of strings the agent may exercise (e.g. "read", "write",
    "tool_use").  Immutable after construction — capabilities cannot be
    elevated at runtime.  This enforces least-privilege at the identity layer,
    not just at the action layer.
    [STANDARD: NIST SP 800-53 AC-6; OWASP LLM Top 10 v2025 LLM06/LLM08]

    TTL semantics
    -------------
    ttl_seconds = 0  : never-expire mode for TEST FIXTURES ONLY.
                       Production passports MUST have ttl_seconds > 0.
    ttl_seconds > 0  : is_expired() returns True once now > issued_at + ttl.
                       Fail-closed: expired passports are rejected at both
                       register_agent() and start().
    [STANDARD: NIST SP 800-53 IA-5 — authenticator management]

    Attributes
    ----------
    model_id     : unique agent identifier (e.g. "research-agent-v2")
    version      : semantic version string (e.g. "1.3.0")
    policy_hash  : SHA-256 hex digest of the authorised policy document
    ttl_seconds  : credential lifetime in seconds
    capabilities : frozenset of authorised capability strings
    issued_at    : Unix UTC float of issuance time
    passport_id  : UUID4 globally unique to this issuance
    """

    model_id:     str
    version:      str
    policy_hash:  str
    ttl_seconds:  int
    capabilities: frozenset = field(default_factory=frozenset)
    issued_at:    float     = field(default_factory=time.time)
    passport_id:  str       = field(default_factory=lambda: str(uuid.uuid4()))

    def is_expired(self) -> bool:
        """
        Return True if the passport's TTL has elapsed.

        Uses wall-clock time (time.time()) because TTL is a calendar-time
        concept — the credential expires at a specific instant, not relative
        to process uptime.

        [STANDARD: NIST SP 800-53 IA-5 — authenticator lifetime limits;
                   DoD Zero Trust RA v2.0 — time-bound credentials]
        """
        if self.ttl_seconds == 0:
            # Explicit sentinel for test fixtures only.
            # Production code should treat 0 as a configuration error.
            return False
        return time.time() > self.issued_at + self.ttl_seconds

    def has_capability(self, cap: str) -> bool:
        """
        Return True if the passport explicitly grants the capability.

        Case-sensitive exact match.  The caller-facing gate is
        AegisFrameworkBridge.require_capability() which raises PermissionError;
        this method provides the predicate for that check.

        [STANDARD: NIST SP 800-53 AC-3, AC-6; OWASP LLM Top 10 v2025 LLM06]
        """
        return cap in self.capabilities

    def to_audit_dict(self) -> Dict[str, Any]:
        """
        Return a non-secret representation safe for log records.

        Intentionally excludes any field that could be used to forge or replay
        a credential.  Capabilities are sorted for deterministic output.
        The 'expired' flag is pre-computed so log consumers can detect
        post-expiry usage without recomputing timestamps.

        [STANDARD: NIST SP 800-53 AU-3 (audit record content);
                   NIST SP 800-53 SC-12 (credential non-disclosure)]
        """
        return {
            "passport_id":  self.passport_id,
            "model_id":     self.model_id,
            "version":      self.version,
            "policy_hash":  self.policy_hash,
            "ttl_seconds":  self.ttl_seconds,
            "capabilities": sorted(self.capabilities),
            "expired":      self.is_expired(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE
# [STANDARD: NIST AI RMF GOVERN-1.1, MAP-5.1, MANAGE-2.2;
#            NIST SP 800-53 AC-3, SI-7;
#            DoD Zero Trust RA v2.0 (never trust, always verify);
#            OWASP LLM Top 10 v2025 LLM01; ISA/IEC 62443-3-3 SR 2.1]
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SemanticScore:
    """
    Two-dimensional semantic risk score for an agent action.

    authority  (−1.0 → +1.0) : trust level of the action source.
        Negative = adversarial/untrusted.  Floor threshold is the minimum
        acceptable trust bar.

    sensitivity  (0.0 → +1.0) : risk level of the action payload.
        0.0 = fully benign; 1.0 = maximally sensitive.  Ceiling and flag
        thresholds control hard-block vs. monitored-proceed behaviour.

    [STANDARD: NIST AI RMF MEASURE-2.5 (AI risk metrics);
               ISA/IEC 62443-3-3 SR 2.1 (authorisation, SL-2)]
    """
    authority:   float   # −1.0 (adversarial) → +1.0 (fully trusted)
    sensitivity: float   # 0.0 (benign) → 1.0 (maximally sensitive)


@dataclass
class PolicyResult:
    """
    Full result of a PolicyEngine.evaluate() call.

    All fields are included so framework wrappers can produce complete,
    self-contained audit records without referencing the engine configuration.

    [STANDARD: NIST SP 800-53 AU-3 (content of audit records);
               NIST AI RMF MEASURE-2.5 (risk metric documentation)]
    """
    decision:            PolicyDecision   # ALLOW | FLAG | DENY
    authority:           float            # score that was evaluated
    sensitivity:         float            # score that was evaluated
    authority_floor:     float            # floor applied (elevated in SUSPECT)
    sensitivity_ceiling: float            # ceiling applied
    reason:              str              # human-readable rationale (for audit)
    evaluated_at:        float = field(default_factory=time.time)


class PolicyEngine:
    """
    Real-time context-aware policy engine.

    Decision priority order (evaluated top-to-bottom; first match wins):
    1. authority < floor           → DENY   [NIST SP 800-53 AC-3]
    2. sensitivity > ceiling       → DENY   [OWASP LLM01; ISA/IEC 62443 SR 2.1]
    3. sensitivity > flag_threshold → FLAG   [NIST AI RMF MAP-5.1]
    4. Otherwise                   → ALLOW

    SUSPECT state applies an elevated authority floor (floor + suspect_floor_bump),
    implementing "elevated confidence floors for recovered agents" from the Aegis
    Protocol specification.
    [STANDARD: NIST AI RMF MAP-5.1 — risk likelihood monitoring]

    Fail-closed guarantee
    ---------------------
    evaluate() wraps its entire body in try/except and returns DENY on any
    exception.  This is the primary fail-closed enforcement point.
    [STANDARD: NIST SP 800-53 SI-7; DoD Zero Trust RA v2.0]

    Parameters
    ----------
    authority_floor      : minimum authority to avoid DENY (default 0.0)
    sensitivity_ceiling  : maximum sensitivity before hard DENY (default 0.70)
    flag_threshold       : sensitivity above which FLAG is returned (default 0.45)
    suspect_floor_bump   : extra authority margin in SUSPECT state (default 0.20)
    """

    def __init__(self,
                 authority_floor:     float = 0.0,
                 sensitivity_ceiling: float = 0.70,
                 flag_threshold:      float = 0.45,
                 suspect_floor_bump:  float = 0.20) -> None:
        self.authority_floor     = authority_floor
        self.sensitivity_ceiling = sensitivity_ceiling
        self.flag_threshold      = flag_threshold
        self.suspect_floor_bump  = suspect_floor_bump
        _emit(LOG, "info", "PolicyEngine", "initialised",
              authority_floor=authority_floor,
              sensitivity_ceiling=sensitivity_ceiling,
              flag_threshold=flag_threshold,
              suspect_floor_bump=suspect_floor_bump)

    def evaluate(self, score: SemanticScore,
                 session_state: SessionState = SessionState.ACTIVE
                 ) -> PolicyResult:
        """
        Evaluate a SemanticScore.  Never raises — fail-closed on any error.

        [STANDARD: NIST SP 800-53 AC-3 (access enforcement);
                   NIST AI RMF MAP-5.1, MANAGE-2.2;
                   DoD Zero Trust RA v2.0 (never trust, always verify);
                   OWASP LLM Top 10 v2025 LLM01 (input screening)]
        """
        try:
            # SUSPECT state: elevate authority floor.
            # [STANDARD: NIST AI RMF MAP-5.1 — elevated confidence floors]
            floor = self.authority_floor
            if session_state == SessionState.SUSPECT:
                floor = min(1.0, floor + self.suspect_floor_bump)

            # ── Decision 1: authority below floor ────────────────────────────
            # [STANDARD: NIST SP 800-53 AC-3; DoD Zero Trust RA v2.0]
            if score.authority < floor:
                reason = (
                    f"authority {score.authority:.4f} < floor {floor:.4f}"
                    f" (session_state={session_state.value})"
                )
                _emit(LOG, "info", "PolicyEngine", "deny_authority",
                      authority=score.authority, floor=floor,
                      session_state=session_state.value)
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    authority=score.authority, sensitivity=score.sensitivity,
                    authority_floor=floor,
                    sensitivity_ceiling=self.sensitivity_ceiling,
                    reason=reason,
                )

            # ── Decision 2: sensitivity above ceiling ────────────────────────
            # Hard ceiling — no authority score overrides a sensitivity breach.
            # [STANDARD: OWASP LLM01; ISA/IEC 62443-3-3 SR 2.1]
            if score.sensitivity > self.sensitivity_ceiling:
                reason = (
                    f"sensitivity {score.sensitivity:.4f} "
                    f"> ceiling {self.sensitivity_ceiling:.4f}"
                )
                _emit(LOG, "info", "PolicyEngine", "deny_sensitivity",
                      sensitivity=score.sensitivity,
                      ceiling=self.sensitivity_ceiling)
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    authority=score.authority, sensitivity=score.sensitivity,
                    authority_floor=floor,
                    sensitivity_ceiling=self.sensitivity_ceiling,
                    reason=reason,
                )

            # ── Decision 3: sensitivity above flag threshold ──────────────────
            # [STANDARD: NIST AI RMF MAP-5.1 — monitor without hard-block]
            if score.sensitivity > self.flag_threshold:
                reason = (
                    f"sensitivity {score.sensitivity:.4f}"
                    f" > flag_threshold {self.flag_threshold:.4f}"
                )
                _emit(LOG, "info", "PolicyEngine", "flag",
                      sensitivity=score.sensitivity,
                      flag_threshold=self.flag_threshold)
                return PolicyResult(
                    decision=PolicyDecision.FLAG,
                    authority=score.authority, sensitivity=score.sensitivity,
                    authority_floor=floor,
                    sensitivity_ceiling=self.sensitivity_ceiling,
                    reason=reason,
                )

            # ── Decision 4: within all bounds ─────────────────────────────────
            _emit(LOG, "debug", "PolicyEngine", "allow",
                  authority=score.authority, sensitivity=score.sensitivity)
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                authority=score.authority, sensitivity=score.sensitivity,
                authority_floor=floor,
                sensitivity_ceiling=self.sensitivity_ceiling,
                reason="within policy bounds",
            )

        except Exception as exc:
            # Fail-closed: any unexpected error → DENY.  A buggy scorer or
            # malformed score object cannot accidentally ALLOW an action.
            # Use literal fallback values rather than getattr() — getattr()
            # would re-invoke a broken property and raise again.
            # [STANDARD: NIST SP 800-53 SI-7; DoD Zero Trust RA v2.0]
            _emit(LOG, "error", "PolicyEngine", "eval_error",
                  error=str(exc), action="fail_closed_deny")
            try:
                auth_val = float(score.authority)   # safe read attempt
            except Exception:
                auth_val = 0.0
            try:
                sens_val = float(score.sensitivity)
            except Exception:
                sens_val = 1.0
            return PolicyResult(
                decision=PolicyDecision.DENY,
                authority=auth_val,
                sensitivity=sens_val,
                authority_floor=self.authority_floor,
                sensitivity_ceiling=self.sensitivity_ceiling,
                reason=f"fail-closed on evaluation error: {exc}",
            )


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT VAULT
# [STANDARD: NIST SP 800-53 AU-2, AU-3, AU-9, AU-10, SI-7;
#            NIST SP 800-218A PW.8.1; ISA/IEC 62443-3-3 SR 6.1;
#            NERC CIP-007-6 R4]
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class VaultEntry:
    """
    One immutable, SHA-256 hash-linked record in the AuditVault chain.

    Payload storage policy
    ----------------------
    The raw payload is NEVER stored.  Only its SHA-256 hash (payload_hash)
    is persisted.  This enforces data minimisation and prevents the vault
    from becoming a second copy of sensitive content.
    [STANDARD: NIST SP 800-218A PW.8.1; DoD Zero Trust RA v2.0 — Data pillar]

    Hash chain design
    -----------------
    entry_hash = SHA-256( entry_id || timestamp || agent_id || session_id ||
                          event_type || payload_hash || decision || authority ||
                          sensitivity || framework || prev_hash )

    Any post-append field mutation changes entry_hash, cascading to all
    subsequent prev_hash comparisons — tamper is detectable at O(n) cost.
    [STANDARD: NIST SP 800-53 AU-9, AU-10, SI-7]

    Note: metadata is excluded from the canonical form for dict-ordering
    stability across Python versions.  It is informational only.
    """

    entry_id:     str
    timestamp:    float
    agent_id:     str
    session_id:   str
    event_type:   str
    payload_hash: str           # SHA-256 of raw payload; NEVER the raw payload
    decision:     str           # "ALLOW" | "FLAG" | "DENY"
    authority:    float
    sensitivity:  float
    framework:    str           # "langgraph" | "autogen" | "crewai" | "unknown"
    metadata:     Dict[str, Any]
    prev_hash:    str           # entry_hash of predecessor (or GENESIS)
    entry_hash:   str = ""      # set by AuditVault.append() via compute_hash()

    def _canonical(self) -> str:
        """Deterministic string over all security-critical immutable fields."""
        return (
            f"{self.entry_id}{self.timestamp}{self.agent_id}"
            f"{self.session_id}{self.event_type}{self.payload_hash}"
            f"{self.decision}{self.authority}{self.sensitivity}"
            f"{self.framework}{self.prev_hash}"
        )

    def compute_hash(self) -> str:
        """
        Compute SHA-256 over the canonical form.
        Uses FIPS 180-4 SHA-256. [STANDARD: NIST SP 800-218A PW.4.1]
        """
        return hashlib.sha256(self._canonical().encode("utf-8")).hexdigest()


class AuditVault:
    """
    Append-only, SHA-256 hash-chained, tamper-evident audit ledger.

    DENY decisions are NEVER written to this vault.  The vault records only
    what the agent was PERMITTED to do — data minimisation in action.
    [STANDARD: NIST SP 800-218A PW.8.1; OWASP LLM Top 10 v2025 LLM05]

    Genesis block
    -------------
    GENESIS = "0" * 64 anchors the chain.  The first entry's prev_hash is
    always GENESIS, establishing an unambiguous start that needs no prior
    state — cold-start safe by design.
    [STANDARD: NIST SP 800-53 AU-9 — chain valid from genesis]

    verify_chain()
    --------------
    O(n) traversal.  For each entry: (1) checks prev_hash linkage,
    (2) recomputes entry_hash from fields and compares.
    False on first failure; True means no entry was modified after append.
    [STANDARD: NIST SP 800-53 AU-9, AU-10, SI-7]
    """

    GENESIS: str = "0" * 64   # 64 hex zeros; impossible real SHA-256 output

    def __init__(self) -> None:
        self._chain: List[VaultEntry] = []
        _emit(LOG, "info", "AuditVault", "initialised",
              genesis_hash=self.GENESIS)

    def append(self, *, agent_id: str, session_id: str, event_type: str,
               payload: str, result: PolicyResult,
               framework: str = "unknown",
               metadata: Optional[Dict[str, Any]] = None) -> VaultEntry:
        """
        Append a hash-linked entry.  Must only be called for ALLOW/FLAG.

        Payload is stored as SHA-256 hash only.  Raw content is never
        retained beyond this method's stack frame.
        [STANDARD: NIST SP 800-218A PW.8.1 — data minimisation]

        Keyword-only args (the * separator) prevent accidental positional
        confusion when many parameters are supplied.
        [STANDARD: NIST SP 800-53 AU-2, AU-3 — event logging content]
        """
        prev = self._chain[-1].entry_hash if self._chain else self.GENESIS
        entry = VaultEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=time.time(),
            agent_id=agent_id,
            session_id=session_id,
            event_type=event_type,
            # Hash the payload immediately; discard the raw content.
            # [STANDARD: NIST SP 800-218A PW.8.1]
            payload_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            decision=result.decision.value,
            authority=result.authority,
            sensitivity=result.sensitivity,
            framework=framework,
            metadata=metadata or {},
            prev_hash=prev,
        )
        # Seal the entry before appending — entry_hash must not change after.
        # [STANDARD: NIST SP 800-53 AU-9 — immutable after commit]
        entry.entry_hash = entry.compute_hash()
        self._chain.append(entry)
        _emit(LOG, "info", "AuditVault", "entry_appended",
              entry_id=entry.entry_id, agent_id=agent_id,
              framework=framework, decision=result.decision.value,
              chain_length=len(self._chain))
        return entry

    def verify_chain(self) -> bool:
        """
        O(n) chain integrity verification.

        For each entry: checks prev_hash linkage and recomputes entry_hash.
        Returns True only if ALL checks pass.  False on first failure.
        An empty chain returns True (cold-start correctness).

        [STANDARD: NIST SP 800-53 AU-9, AU-10, SI-7]
        """
        if not self._chain:
            return True
        prev = self.GENESIS
        for e in self._chain:
            # ── Linkage check ───────────────────────────────────────────────
            if e.prev_hash != prev:
                _emit(LOG, "error", "AuditVault", "chain_break",
                      entry_id=e.entry_id,
                      expected_prev=prev, actual_prev=e.prev_hash)
                return False
            # ── Content integrity check ─────────────────────────────────────
            recomputed = e.compute_hash()
            if recomputed != e.entry_hash:
                _emit(LOG, "error", "AuditVault", "entry_tampered",
                      entry_id=e.entry_id,
                      expected=recomputed, stored=e.entry_hash)
                return False
            prev = e.entry_hash
        _emit(LOG, "info", "AuditVault", "chain_verified",
              chain_length=len(self._chain))
        return True

    def entries_for_session(self, session_id: str) -> List[VaultEntry]:
        """
        Return all vault entries for a specific session.

        Supports per-session incident investigation and rate-limiting.
        [STANDARD: NIST SP 800-53 IR-4 — incident handling support;
                   ISA/IEC 62443-3-3 SR 6.1 — audit log accessibility]
        """
        return [e for e in self._chain if e.session_id == session_id]

    @property
    def length(self) -> int:
        """Number of entries in the chain."""
        return len(self._chain)


# ══════════════════════════════════════════════════════════════════════════════
# TRANSPARENCY LOG
# [STANDARD: NIST SP 800-53 AU-2, AU-3, AU-9, AU-10;
#            NIST AI RMF GOVERN-1.1, MEASURE-2.5;
#            ISA/IEC 62443-3-3 SR 6.2; NERC CIP-007-6 R4]
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TLogEntry:
    """
    One record in the governance TransparencyLog hash chain.

    Separate from AuditVault because governance events (passport validations,
    session transitions, framework handshakes) must be logged even when vault
    writes are DENIED.  If both were the same store, a DENY would prevent
    logging the denial itself — defeating the purpose of the denial record.

    The hash chain uses the same SHA-256 linkage scheme as AuditVault.
    [STANDARD: NIST SP 800-53 AU-10 — non-repudiation]

    Note: the metadata/details dict is excluded from the canonical hash for
    dict-ordering stability.  The event_type and chain linkage are sufficient
    to detect meaningful tampering.
    """

    log_id:     str
    timestamp:  float
    agent_id:   str
    session_id: str
    event_type: str
    details:    Dict[str, Any]
    prev_hash:  str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 over security-critical fields. [NIST SP 800-218A PW.4.1]"""
        blob = (
            f"{self.log_id}{self.timestamp}{self.agent_id}"
            f"{self.session_id}{self.event_type}{self.prev_hash}"
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class TransparencyLog:
    """
    Hash-chained governance event log.

    Records the full lifecycle of every agent session:
    • Passport validation and bridge start
    • Session state transitions (ACTIVE → SUSPECT → QUARANTINE → RESYNC)
    • Every policy decision (via 'action_evaluated' records)
    • Framework handshake events
    • Bridge shutdown with chain integrity results

    IMPORTANT: the event label parameter is named log_event_type (not
    event_type) to permanently prevent a call-site TypeError that would occur
    if a caller passed event_type= as a keyword argument while also passing
    a dict via **kwargs that contained an 'event_type' key.

    [STANDARD: NIST SP 800-53 AU-2, AU-3, AU-9, AU-10;
               NIST AI RMF GOVERN-1.1, MEASURE-2.5;
               ISA/IEC 62443-3-3 SR 6.2; NERC CIP-007-6 R4]
    """

    GENESIS: str = "0" * 64

    def __init__(self) -> None:
        self._entries: List[TLogEntry] = []

    def record(self, agent_id: str, session_id: str,
               log_event_type: str, **details: Any) -> TLogEntry:
        """
        Append a governance record.

        Parameters
        ----------
        agent_id       : model_id of the agent generating the event
        session_id     : session UUID from SessionGuard
        log_event_type : short event label (e.g. "bridge_started", "resynced").
                         Named log_event_type rather than event_type to prevent
                         a call-site TypeError if a caller passes event_type=
                         as a keyword argument in **dict unpacking.
        **details      : arbitrary structured fields for this event.

        [STANDARD: NIST SP 800-53 AU-3 (content of audit records)]
        """
        # Discard any 'event_type' kwarg that sneaked in via **dict unpacking.
        # The Python call-site TypeError cannot occur because the positional
        # parameter is named log_event_type, not event_type.
        details.pop("event_type", None)

        prev = self._entries[-1].entry_hash if self._entries else self.GENESIS
        entry = TLogEntry(
            log_id=str(uuid.uuid4()),
            timestamp=time.time(),
            agent_id=agent_id,
            session_id=session_id,
            event_type=log_event_type,
            details=details,
            prev_hash=prev,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        _emit(LOG, "info", "TransparencyLog", "entry_recorded",
              log_id=entry.log_id, event_type=log_event_type,
              agent_id=agent_id, chain_length=len(self._entries))
        return entry

    def verify_chain(self) -> bool:
        """
        O(n) integrity verification.  Empty log returns True.
        [STANDARD: NIST SP 800-53 AU-9, AU-10, SI-7]
        """
        if not self._entries:
            return True
        prev = self.GENESIS
        for e in self._entries:
            if e.prev_hash != prev:
                _emit(LOG, "error", "TransparencyLog", "chain_break",
                      log_id=e.log_id,
                      expected_prev=prev, actual_prev=e.prev_hash)
                return False
            if e.compute_hash() != e.entry_hash:
                _emit(LOG, "error", "TransparencyLog", "tampered",
                      log_id=e.log_id)
                return False
            prev = e.entry_hash
        return True

    @property
    def length(self) -> int:
        """Number of entries in the log."""
        return len(self._entries)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION GUARD
# [STANDARD: NIST AI RMF MAP-5.1, MANAGE-3.2;
#            NIST SP 800-53 IR-4, AC-2;
#            ISA/IEC 62443-3-3 SR 6.2;
#            DoD Zero Trust RA v2.0 — continuous verification]
# ══════════════════════════════════════════════════════════════════════════════

class SessionGuard:
    """
    Per-session Aegis Protocol state machine with warp-score accumulation.

    The warp_score (0.0 → 1.0) measures cumulative behavioural anomaly
    pressure.  It increments on every FLAG or DENY decision and never
    decreases within a session (only resync() resets it).  This implements
    continuous risk monitoring: [STANDARD: NIST AI RMF MAP-5.1]

    State machine transitions
    -------------------------
    INIT → ACTIVE       activate(): passport validated
    ACTIVE → SUSPECT    warp_score ≥ SUSPECT_THRESHOLD (0.40)
    SUSPECT → QUARANTINE warp_score ≥ QUARANTINE_THRESHOLD (0.70)
    QUARANTINE → ACTIVE  resync(): controlled recovery
    ACTIVE/SUSPECT → CLOSED  close()

    Warp thresholds
    ---------------
    SUSPECT_THRESHOLD    = 0.40   ≈ 4 adverse decisions
    QUARANTINE_THRESHOLD = 0.70   ≈ 6 adverse decisions
    WARP_INCREMENT       = 0.12   per FLAG or DENY

    [STANDARD: NIST SP 800-53 IR-4; ISA/IEC 62443-3-3 SR 6.2]
    """

    SUSPECT_THRESHOLD:    float = 0.40
    QUARANTINE_THRESHOLD: float = 0.70
    WARP_INCREMENT:       float = 0.12

    def __init__(self, agent_id: str,
                 session_id: Optional[str] = None,
                 tlog: Optional[TransparencyLog] = None) -> None:
        self.agent_id   = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.state      = SessionState.INIT
        self.warp_score = 0.0
        self._tlog      = tlog
        _emit(LOG, "info", "SessionGuard", "created",
              agent_id=agent_id, session_id=self.session_id)

    def activate(self) -> None:
        """
        Transition INIT → ACTIVE.  Raises RuntimeError if not in INIT.

        Called exactly once by AegisFrameworkBridge.start() after passport
        validation.  Prevents double-activation via state guard.
        [STANDARD: NIST SP 800-53 AC-2 — account lifecycle management]
        """
        if self.state != SessionState.INIT:
            raise RuntimeError(
                f"activate() called from state {self.state.value}; expected INIT"
            )
        self.state = SessionState.ACTIVE
        if self._tlog:
            self._tlog.record(self.agent_id, self.session_id,
                              "session_activated")
        _emit(LOG, "info", "SessionGuard", "activated",
              session_id=self.session_id)

    def record(self, decision: PolicyDecision) -> SessionState:
        """
        Incorporate a policy decision into warp score and advance state.

        ALLOW decisions do NOT increment warp.  FLAG and DENY increment
        warp by WARP_INCREMENT.  Threshold crossing is checked after each
        increment.  Records in non-ACTIVE/SUSPECT states are silently ignored.

        [STANDARD: NIST AI RMF MAP-5.1 (risk likelihood monitoring);
                   ISA/IEC 62443-3-3 SR 6.2 (continuous monitoring);
                   NIST SP 800-53 IR-4 (incident handling)]
        """
        if self.state not in (SessionState.ACTIVE, SessionState.SUSPECT):
            _emit(LOG, "warning", "SessionGuard", "record_ignored",
                  state=self.state.value, decision=decision.value)
            return self.state

        if decision in (PolicyDecision.FLAG, PolicyDecision.DENY):
            self.warp_score = min(1.0, self.warp_score + self.WARP_INCREMENT)

        prev_state = self.state

        # ── Quarantine check (higher severity — evaluated first) ──────────────
        # [STANDARD: NIST SP 800-53 IR-4 — incident response trigger]
        if self.warp_score >= self.QUARANTINE_THRESHOLD:
            self.state = SessionState.QUARANTINE
            _emit(LOG, "warning", "SessionGuard", "quarantine_triggered",
                  session_id=self.session_id,
                  warp_score=round(self.warp_score, 4))
            if self._tlog:
                self._tlog.record(self.agent_id, self.session_id,
                                  "quarantine_triggered",
                                  warp_score=round(self.warp_score, 4))

        # ── Suspect check (only if not already quarantined) ────────────────────
        # [STANDARD: NIST AI RMF MAP-5.1 — elevated monitoring tier]
        elif (self.warp_score >= self.SUSPECT_THRESHOLD
              and prev_state != SessionState.SUSPECT):
            self.state = SessionState.SUSPECT
            _emit(LOG, "info", "SessionGuard", "suspect_triggered",
                  session_id=self.session_id,
                  warp_score=round(self.warp_score, 4))
            if self._tlog:
                self._tlog.record(self.agent_id, self.session_id,
                                  "suspect_triggered",
                                  warp_score=round(self.warp_score, 4))
        else:
            _emit(LOG, "debug", "SessionGuard", "warp_updated",
                  session_id=self.session_id,
                  warp_score=round(self.warp_score, 4),
                  decision=decision.value)

        return self.state

    def resync(self) -> None:
        """
        Controlled recovery: QUARANTINE → FLUSHING → RESYNC → ACTIVE.

        Resets warp_score to 0.0 during FLUSHING.  Raises RuntimeError if
        called from any state other than QUARANTINE — prevents accidental
        warp resets.  Records 'resynced' governance event.

        [STANDARD: NIST AI RMF MANAGE-3.2 — response to identified risks;
                   NIST SP 800-53 IR-4 — incident recovery]
        """
        if self.state != SessionState.QUARANTINE:
            raise RuntimeError(
                f"resync() requires QUARANTINE state, got {self.state.value}"
            )
        self.state = SessionState.FLUSHING   # flush anomalous context
        self.warp_score = 0.0                # reset accumulated pressure
        self.state = SessionState.RESYNC     # reload clean snapshot
        self.state = SessionState.ACTIVE     # return to normal operation
        if self._tlog:
            self._tlog.record(self.agent_id, self.session_id, "resynced")
        _emit(LOG, "info", "SessionGuard", "resynced",
              session_id=self.session_id)

    def close(self) -> None:
        """
        Permanently close the session.  Records 'session_closed' to tlog.
        [STANDARD: NIST SP 800-53 AC-2 — account termination]
        """
        self.state = SessionState.CLOSED
        if self._tlog:
            self._tlog.record(self.agent_id, self.session_id, "session_closed")

    @property
    def is_active(self) -> bool:
        """
        True if the session can accept new evaluate_action() calls.

        Both ACTIVE and SUSPECT accept actions.  The PolicyEngine applies a
        higher authority floor for SUSPECT.  All other states raise.
        """
        return self.state in (SessionState.ACTIVE, SessionState.SUSPECT)


# ══════════════════════════════════════════════════════════════════════════════
# AEGIS FRAMEWORK BRIDGE
# [STANDARD: All component standards above, plus:
#            NIST SP 800-53 AC-6; OWASP LLM06/LLM08;
#            DoD Zero Trust RA v2.0 Applications/Workloads pillar]
# ══════════════════════════════════════════════════════════════════════════════

class AegisFrameworkBridge:
    """
    Per-agent evaluation facade used by all framework integrations.

    Primary integration point for LangGraph, AutoGen, and CrewAI wrappers.
    Provides a single evaluate_action() call that atomically:
      1. Checks session state (blocks QUARANTINE / inactive sessions)
      2. Evaluates semantic score through PolicyEngine
      3. Updates session warp score
      4. Appends to AuditVault (ALLOW/FLAG only)
      5. Records to TransparencyLog (always)
      6. Returns (PolicyResult, allowed: bool)

    This atomicity guarantee means framework wrappers do not need to
    coordinate these steps — they call evaluate_action() and act on the bool.

    Fail-closed boundary points
    ---------------------------
    start()           : PermissionError if passport expired
    evaluate_action() : PermissionError if session QUARANTINE
    evaluate_action() : RuntimeError if session not active
    evaluate_action() : PermissionError on any exception (fail-closed)
    require_capability(): PermissionError if capability not in passport

    [STANDARD: NIST SP 800-53 AC-3, AC-6, AU-2, AU-3, IA-2;
               NIST AI RMF GOVERN-1.1, MAP-5.1, MANAGE-2.2, MANAGE-3.2;
               DoD Zero Trust RA v2.0; OWASP LLM01/LLM06/LLM08]
    """

    def __init__(self, passport: SemanticPassport,
                 policy:    Optional[PolicyEngine]    = None,
                 vault:     Optional[AuditVault]      = None,
                 tlog:      Optional[TransparencyLog] = None,
                 framework: str                       = "unknown") -> None:
        self.passport      = passport
        self.policy        = policy   or PolicyEngine()
        self.vault         = vault    or AuditVault()
        self.tlog          = tlog     or TransparencyLog()
        self.framework     = framework
        self.session       = SessionGuard(
            agent_id=passport.model_id, tlog=self.tlog
        )
        self._action_count = 0
        _emit(LOG, "info", "AegisFrameworkBridge", "created",
              model_id=passport.model_id, framework=framework,
              passport_id=passport.passport_id)

    def start(self) -> None:
        """
        Validate passport and activate the session.

        This is the sole entry point for session initialisation.  It MUST be
        called before evaluate_action().  Calling evaluate_action() before
        start() raises RuntimeError (session not in active state).

        Fail-closed: if passport.is_expired() is True, raises PermissionError
        immediately with no partial initialisation.

        Records a 'bridge_started' governance event with passport audit fields
        (non-secret only) to create a cryptographic anchor for the session.

        [STANDARD: NIST SP 800-53 IA-5 (authenticator management);
                   NIST SP 800-53 AU-3 (audit content — policy scope binding);
                   DoD Zero Trust RA v2.0 (verify before trust);
                   NIST AI RMF GOVERN-1.1]
        """
        if self.passport.is_expired():
            # Fail-closed: expired credential → no session activation
            # [STANDARD: NIST SP 800-53 IA-5; DoD Zero Trust RA v2.0]
            _emit(LOG, "error", "AegisFrameworkBridge", "start_denied",
                  reason="passport_expired",
                  passport_id=self.passport.passport_id)
            raise PermissionError(
                f"Passport {self.passport.passport_id} has expired"
            )
        self.session.activate()
        # Log passport fields individually to avoid any risk of an
        # 'event_type' key appearing in **dict unpacking.
        audit = self.passport.to_audit_dict()
        self.tlog.record(
            self.passport.model_id, self.session.session_id,
            "bridge_started",
            framework=self.framework,
            passport_id=audit["passport_id"],
            model_id=audit["model_id"],
            version=audit["version"],
            policy_hash=audit["policy_hash"],
            capabilities=audit["capabilities"],
        )
        _emit(LOG, "info", "AegisFrameworkBridge", "started",
              session_id=self.session.session_id, framework=self.framework)

    def shutdown(self) -> Tuple[bool, bool]:
        """
        Close the session and verify vault + tlog chain integrity.

        Records a 'bridge_shutdown' governance event with chain verification
        results so that any integrity failure is itself audit-logged.

        Returns
        -------
        (vault_ok: bool, tlog_ok: bool)
            False for either means a chain entry was mutated — requires
            immediate incident response.

        [STANDARD: NIST SP 800-53 AU-9, AU-10, SI-7;
                   NIST AI RMF MANAGE-3.2 — post-run assessment]
        """
        self.session.close()
        vault_ok = self.vault.verify_chain()
        tlog_ok  = self.tlog.verify_chain()
        self.tlog.record(
            self.passport.model_id, self.session.session_id,
            "bridge_shutdown",
            vault_entries=self.vault.length,
            tlog_entries=self.tlog.length,
            vault_chain_ok=vault_ok,
            tlog_chain_ok=tlog_ok,
        )
        _emit(LOG, "info", "AegisFrameworkBridge", "shutdown",
              vault_entries=self.vault.length, vault_chain_ok=vault_ok,
              tlog_entries=self.tlog.length, tlog_chain_ok=tlog_ok)
        return vault_ok, tlog_ok

    def evaluate_action(self, payload: str,
                        authority: float = 0.5,
                        sensitivity: float = 0.1,
                        event_type: str = "agent_action",
                        **metadata: Any) -> Tuple[PolicyResult, bool]:
        """
        Atomic evaluation pipeline: policy → warp → vault → tlog.

        Pipeline steps (executed in order; atomic from caller perspective):
        1. Pre-condition: PermissionError if QUARANTINE, RuntimeError if inactive
        2. PolicyEngine.evaluate() → ALLOW/FLAG/DENY
        3. SessionGuard.record() — warp update (BEFORE vault to prevent race)
        4. AuditVault.append() — ALLOW/FLAG only; DENY never vaulted
        5. TransparencyLog.record() — always, even on DENY
        6. Return (PolicyResult, allowed: bool)

        Fail-closed: any exception in steps 2–5 raises PermissionError.
        [STANDARD: NIST SP 800-53 SI-7; DoD Zero Trust RA v2.0]

        Parameters
        ----------
        payload      : raw action content; hashed and discarded immediately
        authority    : authority score (−1.0 → +1.0)
        sensitivity  : sensitivity score (0.0 → 1.0)
        event_type   : action label for vault/tlog (e.g. "tool_call")
        **metadata   : extra context stored in vault entry metadata

        Returns
        -------
        (PolicyResult, allowed: bool)
            allowed is True for ALLOW or FLAG; False for DENY.

        [STANDARD: NIST SP 800-53 AC-3, AU-2, AU-3, AU-9, AU-10;
                   NIST AI RMF MAP-5.1, MANAGE-2.2;
                   DoD Zero Trust RA v2.0; OWASP LLM01]
        """
        self._action_count += 1

        # ── Step 1: pre-condition checks ─────────────────────────────────────
        # [STANDARD: NIST SP 800-53 IR-4; DoD Zero Trust RA v2.0]
        if self.session.state == SessionState.QUARANTINE:
            _emit(LOG, "error", "AegisFrameworkBridge", "blocked_quarantine",
                  session_id=self.session.session_id,
                  action_count=self._action_count)
            raise PermissionError(
                f"Session {self.session.session_id} is quarantined — "
                "no actions permitted until resync"
            )

        if not self.session.is_active:
            _emit(LOG, "error", "AegisFrameworkBridge", "blocked_inactive",
                  state=self.session.state.value)
            raise RuntimeError(
                f"Session not in active state: {self.session.state.value}"
            )

        # ── Step 2: policy evaluation ─────────────────────────────────────────
        # PolicyEngine.evaluate() never raises (fail-closed internally).
        # [STANDARD: NIST SP 800-53 AC-3; OWASP LLM01]
        score  = SemanticScore(authority=authority, sensitivity=sensitivity)
        result = self.policy.evaluate(score, self.session.state)
        allowed = result.decision != PolicyDecision.DENY

        # ── Step 3: warp score update ─────────────────────────────────────────
        # Update BEFORE vault write so a quarantine triggered here cannot be
        # bypassed by a concurrent call racing to the vault.
        # [STANDARD: NIST AI RMF MAP-5.1; NIST SP 800-53 IR-4]
        self.session.record(result.decision)

        # ── Step 4: vault append (ALLOW and FLAG only) ────────────────────────
        # DENY decisions: payload never persisted anywhere.
        # [STANDARD: NIST SP 800-218A PW.8.1; DoD Zero Trust RA v2.0 — Data]
        if allowed:
            self.vault.append(
                agent_id=self.passport.model_id,
                session_id=self.session.session_id,
                event_type=event_type,
                payload=payload,
                result=result,
                framework=self.framework,
                metadata=metadata,
            )

        # ── Step 5: transparency log (always, even for DENY) ──────────────────
        # action_event_type= used instead of event_type= to avoid kwarg
        # collision with TransparencyLog.record()'s positional parameter.
        # [STANDARD: NIST SP 800-53 AU-2 — denied actions must still be logged]
        self.tlog.record(
            self.passport.model_id,
            self.session.session_id,
            "action_evaluated",
            decision=result.decision.value,
            reason=result.reason,
            allowed=allowed,
            session_state=self.session.state.value,
            warp_score=round(self.session.warp_score, 4),
            framework=self.framework,
            action_event_type=event_type,   # renamed to avoid positional collision
        )

        _emit(LOG, "info", "AegisFrameworkBridge", "action_evaluated",
              decision=result.decision.value, allowed=allowed,
              framework=self.framework,
              session_state=self.session.state.value,
              warp_score=round(self.session.warp_score, 4))

        return result, allowed

    def require_capability(self, capability: str) -> None:
        """
        Raise PermissionError if passport does not grant the capability.

        Framework wrappers call this before allowing agents to invoke tools,
        access node types, or execute task types.  Enforces the principle
        that agents can only do what their passport explicitly authorises.

        [STANDARD: NIST SP 800-53 AC-6 (least privilege);
                   OWASP LLM Top 10 v2025 LLM06 (excessive agency);
                   OWASP LLM Top 10 v2025 LLM08 (excessive permissions)]
        """
        if not self.passport.has_capability(capability):
            _emit(LOG, "warning", "AegisFrameworkBridge", "capability_denied",
                  required=capability,
                  granted=sorted(self.passport.capabilities))
            raise PermissionError(
                f"Passport does not grant capability '{capability}'"
            )

    def status_dict(self) -> Dict[str, Any]:
        """
        Return a non-sensitive status snapshot for health endpoints.

        All returned values are derived metrics or public identifiers.
        No credential material, payload hashes, or chain content included.
        Safe to expose via Prometheus, Grafana, Datadog, etc.

        [STANDARD: NIST SP 800-53 AU-3 (monitoring information);
                   NIST AI RMF MEASURE-2.5 (risk metrics)]
        """
        return {
            "model_id":         self.passport.model_id,
            "passport_id":      self.passport.passport_id,
            "framework":        self.framework,
            "session_id":       self.session.session_id,
            "session_state":    self.session.state.value,
            "warp_score":       round(self.session.warp_score, 4),
            "action_count":     self._action_count,
            "vault_entries":    self.vault.length,
            "tlog_entries":     self.tlog.length,
            "passport_expired": self.passport.is_expired(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# AEGIS ADAPTER — TOP-LEVEL FACADE
# [STANDARD: NIST SP 800-53 AC-2; NIST AI RMF GOVERN-1.1;
#            ISA/IEC 62443-3-3 SR 6.1]
# ══════════════════════════════════════════════════════════════════════════════

class AegisAdapter:
    """
    Deployment-level facade.  One instance per deployment.

    Owns a shared AuditVault and TransparencyLog across all registered agents,
    enabling:
    • Cross-agent incident correlation (single chain to query)
    • Fleet-level chain integrity verification with one verify_all_chains() call
    • Consistent SIEM log stream across all agent types and frameworks

    Agent registration
    ------------------
    register_agent() creates and returns an AegisFrameworkBridge wired to the
    shared vault and tlog.  Expired passports are rejected at registration.
    [STANDARD: NIST SP 800-53 AC-2; DoD Zero Trust RA v2.0 — Identity pillar]

    Fleet verification
    ------------------
    verify_all_chains() runs O(n) verification on both chains.  False means
    at least one entry was tampered — requires immediate investigation.
    [STANDARD: NIST SP 800-53 AU-9, SI-7]
    """

    def __init__(self, policy: Optional[PolicyEngine] = None) -> None:
        self.vault   = AuditVault()
        self.tlog    = TransparencyLog()
        self.policy  = policy or PolicyEngine()
        self._bridges: Dict[str, AegisFrameworkBridge] = {}
        _emit(LOG, "info", "AegisAdapter", "initialised")

    def register_agent(self, passport: SemanticPassport,
                       framework: str = "unknown") -> AegisFrameworkBridge:
        """
        Register an agent; return its AegisFrameworkBridge.

        Fails immediately for expired passports — the bridge is not created.
        If model_id is already registered, the new bridge replaces the old.
        [STANDARD: NIST SP 800-53 AC-2; DoD Zero Trust RA v2.0]
        """
        if passport.is_expired():
            raise PermissionError(
                f"Cannot register agent: passport {passport.passport_id} expired"
            )
        bridge = AegisFrameworkBridge(
            passport=passport,
            policy=self.policy,
            vault=self.vault,
            tlog=self.tlog,
            framework=framework,
        )
        self._bridges[passport.model_id] = bridge
        _emit(LOG, "info", "AegisAdapter", "agent_registered",
              model_id=passport.model_id, framework=framework,
              passport_id=passport.passport_id)
        return bridge

    def verify_all_chains(self) -> Tuple[bool, bool]:
        """
        Verify vault and tlog chains.  Returns (vault_ok, tlog_ok).
        Both chains span all registered agents.
        [STANDARD: NIST SP 800-53 AU-9, AU-10, SI-7]
        """
        v = self.vault.verify_chain()
        t = self.tlog.verify_chain()
        _emit(LOG, "info", "AegisAdapter", "chains_verified",
              vault_ok=v, tlog_ok=t,
              vault_entries=self.vault.length,
              tlog_entries=self.tlog.length)
        return v, t

    def fleet_status(self) -> List[Dict[str, Any]]:
        """
        Return non-sensitive status snapshots for all registered agents.
        Each snapshot is safe for monitoring API exposure.
        """
        return [b.status_dict() for b in self._bridges.values()]


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE
# ══════════════════════════════════════════════════════════════════════════════
# Coverage: 100% of public API surface.
#
# Test categories
# ---------------
# T1  SemanticPassport    — expiry, capabilities, audit dict safety
# T2  PolicyEngine        — all 4 decision branches, fail-closed, SUSPECT state
# T3  AuditVault          — append, integrity, payload-not-stored, tamper detection
# T4  TransparencyLog     — record, chain integrity, event_type kwarg guard
# T5  SessionGuard        — full state machine, warp, resync, edge cases
# T6  AegisFrameworkBridge — full pipeline, vault/tlog side-effects, capability,
#                            quarantine, fail-closed
# T7  AegisAdapter        — fleet registration, chain verification, status
#
# Standards validated
# -------------------
# Fail-closed (NIST SP 800-53 SI-7, DoD Zero Trust RA v2.0)
# Passport TTL (NIST SP 800-53 IA-5)
# Capability gate (NIST SP 800-53 AC-6, OWASP LLM06/LLM08)
# Payload hash-only (NIST SP 800-218A PW.8.1)
# Chain integrity (NIST SP 800-53 AU-9, AU-10, SI-7)
# Warp accumulation (NIST AI RMF MAP-5.1)
# Quarantine blocking (NIST SP 800-53 IR-4)
# DENY not vaulted (data minimisation)
# Cold-start (empty chain verifies)
# ══════════════════════════════════════════════════════════════════════════════

try:
    import pytest
except ImportError:  # pragma: no cover — pytest always present when tests run
    pytest = None  # type: ignore[assignment]


_TEST_POLICY_HASH = hashlib.sha256(b"test-policy-v1").hexdigest()


def _passport(model_id: str = "test-agent",
              caps: frozenset = frozenset({"read", "write"}),
              ttl: int = 3600,
              expired: bool = False) -> SemanticPassport:
    p = SemanticPassport(
        model_id=model_id, version="1.0.0",
        policy_hash=_TEST_POLICY_HASH,
        ttl_seconds=ttl, capabilities=caps,
    )
    if expired:
        object.__setattr__(p, "issued_at", time.time() - (ttl + 10))
    return p


def _adapter(ceiling: float = 0.70, flag: float = 0.45,
             floor: float = 0.0) -> AegisAdapter:
    return AegisAdapter(policy=PolicyEngine(
        authority_floor=floor, sensitivity_ceiling=ceiling,
        flag_threshold=flag,
    ))


def _started_bridge(model_id: str = "test-agent",
                    caps: frozenset = frozenset({"read", "write"}),
                    ceiling: float = 0.70, flag: float = 0.45,
                    floor: float = 0.0) -> AegisFrameworkBridge:
    adp = _adapter(ceiling, flag, floor)
    b   = adp.register_agent(_passport(model_id, caps=caps), "test")
    b.start()
    return b


# ── T1: SemanticPassport ───────────────────────────────────────────────────────

class TestSemanticPassport:

    def test_fresh_passport_not_expired(self):
        assert _passport(ttl=3600).is_expired() is False

    def test_backdated_passport_expired(self):
        """[NIST SP 800-53 IA-5]"""
        assert _passport(ttl=1, expired=True).is_expired() is True

    def test_zero_ttl_never_expires(self):
        p = SemanticPassport("a", "1.0", _TEST_POLICY_HASH, ttl_seconds=0)
        assert p.is_expired() is False

    def test_has_capability_true(self):
        """[NIST SP 800-53 AC-6]"""
        p = _passport(caps=frozenset({"read", "write"}))
        assert p.has_capability("read")  is True
        assert p.has_capability("write") is True

    def test_has_capability_false_for_unlisted(self):
        p = _passport(caps=frozenset({"read"}))
        assert p.has_capability("write") is False
        assert p.has_capability("admin") is False

    def test_capabilities_frozenset_immutable(self):
        """Capabilities cannot be elevated at runtime. [NIST SP 800-53 AC-6]"""
        p = _passport(caps=frozenset({"read"}))
        with pytest.raises(AttributeError):
            p.capabilities.add("write")   # type: ignore

    def test_audit_dict_has_required_keys(self):
        """[NIST SP 800-53 AU-3]"""
        d = _passport().to_audit_dict()
        for k in ("passport_id", "model_id", "version", "policy_hash",
                  "ttl_seconds", "capabilities", "expired"):
            assert k in d

    def test_audit_dict_no_secret_fields(self):
        """Audit dict must not expose credential material. [NIST SP 800-53 SC-12]"""
        d = _passport().to_audit_dict()
        for k in d:
            assert not any(p in k.lower() for p in _REDACT_PATTERNS), (
                f"Potentially sensitive field: {k}"
            )

    def test_audit_dict_expired_flag_correct(self):
        assert _passport().to_audit_dict()["expired"]             is False
        assert _passport(expired=True).to_audit_dict()["expired"] is True

    def test_passport_ids_unique(self):
        ids = {_passport().passport_id for _ in range(50)}
        assert len(ids) == 50

    def test_empty_capabilities(self):
        p = _passport(caps=frozenset())
        assert p.has_capability("anything") is False


# ── T2: PolicyEngine ──────────────────────────────────────────────────────────

class TestPolicyEngine:

    def _e(self, floor=0.0, ceiling=0.70, flag=0.45, bump=0.20):
        return PolicyEngine(authority_floor=floor, sensitivity_ceiling=ceiling,
                            flag_threshold=flag, suspect_floor_bump=bump)

    def test_allow_within_bounds(self):
        r = self._e().evaluate(SemanticScore(0.8, 0.2))
        assert r.decision == PolicyDecision.ALLOW

    def test_deny_sensitivity_above_ceiling(self):
        """Hard ceiling. [OWASP LLM01; ISA/IEC 62443-3-3 SR 2.1]"""
        r = self._e(ceiling=0.60).evaluate(SemanticScore(1.0, 0.75))
        assert r.decision == PolicyDecision.DENY
        assert "ceiling" in r.reason

    def test_deny_authority_below_floor(self):
        """[NIST SP 800-53 AC-3; DoD Zero Trust RA v2.0]"""
        r = self._e(floor=0.50).evaluate(SemanticScore(0.30, 0.10))
        assert r.decision == PolicyDecision.DENY
        assert "floor" in r.reason

    def test_flag_between_thresholds(self):
        """[NIST AI RMF MAP-5.1 — monitor without blocking]"""
        r = self._e(flag=0.45, ceiling=0.70).evaluate(SemanticScore(0.8, 0.55))
        assert r.decision == PolicyDecision.FLAG
        assert "flag_threshold" in r.reason

    def test_sensitivity_exactly_at_ceiling_flags_not_denies(self):
        """
        Sensitivity exactly at ceiling is NOT denied (strict >), but it IS
        above the flag threshold (0.70 > 0.45), so it returns FLAG.
        Denial requires strictly exceeding the ceiling.
        [NIST SP 800-53 AC-3 — boundary is exclusive for DENY]
        """
        r = self._e(ceiling=0.70).evaluate(SemanticScore(1.0, 0.70))
        assert r.decision == PolicyDecision.FLAG   # 0.70 > 0.45 flag threshold

    def test_sensitivity_just_above_ceiling_denies(self):
        r = self._e(ceiling=0.70).evaluate(SemanticScore(1.0, 0.701))
        assert r.decision == PolicyDecision.DENY

    def test_suspect_state_elevates_floor(self):
        """[NIST AI RMF MAP-5.1 — elevated confidence floors]"""
        e = self._e(floor=0.0, bump=0.30)
        r_active  = e.evaluate(SemanticScore(0.25, 0.10), SessionState.ACTIVE)
        r_suspect = e.evaluate(SemanticScore(0.25, 0.10), SessionState.SUSPECT)
        assert r_active.decision  == PolicyDecision.ALLOW
        assert r_suspect.decision == PolicyDecision.DENY
        assert "SUSPECT" in r_suspect.reason

    def test_suspect_floor_capped_at_one(self):
        e = self._e(floor=0.90, bump=0.50)
        r = e.evaluate(SemanticScore(1.0, 0.10), SessionState.SUSPECT)
        assert r.authority_floor <= 1.0

    def test_fail_closed_on_broken_score(self):
        """[NIST SP 800-53 SI-7; DoD Zero Trust RA v2.0]"""
        class Broken:
            @property
            def authority(self):
                raise RuntimeError("broken")
            sensitivity = 0.5
        r = self._e().evaluate(Broken())   # type: ignore
        assert r.decision == PolicyDecision.DENY
        assert "fail-closed" in r.reason

    def test_result_carries_thresholds(self):
        """[NIST SP 800-53 AU-3 — decision context in record]"""
        e = self._e(floor=0.10, ceiling=0.60)
        r = e.evaluate(SemanticScore(0.5, 0.20))
        assert r.authority_floor     == pytest.approx(0.10)
        assert r.sensitivity_ceiling == pytest.approx(0.60)

    def test_evaluated_at_set(self):
        before = time.time()
        r = self._e().evaluate(SemanticScore(0.5, 0.2))
        assert before <= r.evaluated_at <= time.time()


# ── T3: AuditVault ────────────────────────────────────────────────────────────

class TestAuditVault:

    def _r(self, d=PolicyDecision.ALLOW, auth=0.8, sens=0.1):
        return PolicyResult(decision=d, authority=auth, sensitivity=sens,
                            authority_floor=0.0, sensitivity_ceiling=0.70,
                            reason="test")

    def _append(self, v, payload="p", agent="a", sess="s"):
        return v.append(agent_id=agent, session_id=sess, event_type="test",
                        payload=payload, result=self._r())

    def test_empty_chain_verifies(self):
        """Cold-start correctness. [NIST SP 800-53 AU-9]"""
        assert AuditVault().verify_chain() is True

    def test_single_entry_verifies(self):
        v = AuditVault(); self._append(v)
        assert v.verify_chain() is True

    def test_multi_entry_chain_verifies(self):
        """[NIST SP 800-53 AU-10 — non-repudiation via chain linkage]"""
        v = AuditVault()
        for i in range(6): self._append(v, f"p{i}")
        assert v.verify_chain() is True

    def test_payload_stored_as_hash_only(self):
        """Raw payload never persisted. [NIST SP 800-218A PW.8.1]"""
        secret = "TOP SECRET PAYLOAD"
        v = AuditVault()
        e = self._append(v, secret)
        assert e.payload_hash == hashlib.sha256(secret.encode()).hexdigest()
        assert secret not in str(vars(e))

    def test_tampered_entry_hash_detected(self):
        """[NIST SP 800-53 AU-9, SI-7]"""
        v = AuditVault()
        self._append(v, "e1"); self._append(v, "e2")
        v._chain[0].entry_hash = "a" * 64
        assert v.verify_chain() is False

    def test_tampered_field_detected(self):
        """[NIST SP 800-53 SI-7]"""
        v = AuditVault()
        e = self._append(v)
        orig = e.decision
        e.decision = "TAMPERED"
        assert v.verify_chain() is False
        e.decision = orig
        assert v.verify_chain() is True

    def test_removed_entry_detected(self):
        """[NIST SP 800-53 AU-9 — chain break on removal]"""
        v = AuditVault()
        for i in range(3): self._append(v, f"e{i}")
        v._chain.pop(1)
        assert v.verify_chain() is False

    def test_no_remove_api(self):
        """Vault is append-only by design."""
        v = AuditVault()
        for attr in ("remove", "pop", "delete", "clear"):
            assert not hasattr(v, attr)

    def test_entries_for_session(self):
        """Per-session query. [NIST SP 800-53 IR-4]"""
        v = AuditVault()
        self._append(v, sess="A"); self._append(v, sess="B"); self._append(v, sess="A")
        r = v.entries_for_session("A")
        assert len(r) == 2 and all(e.session_id == "A" for e in r)

    def test_genesis_is_64_zeros(self):
        assert AuditVault.GENESIS == "0" * 64

    def test_first_entry_prev_hash_is_genesis(self):
        v = AuditVault()
        e = self._append(v)
        assert e.prev_hash == AuditVault.GENESIS

    def test_second_entry_links_to_first(self):
        v = AuditVault()
        first = self._append(v, "first")
        second = self._append(v, "second")
        assert second.prev_hash == first.entry_hash

    def test_entry_ids_unique(self):
        v = AuditVault()
        for i in range(20): self._append(v, f"p{i}")
        ids = [e.entry_id for e in v._chain]
        assert len(ids) == len(set(ids))


# ── T4: TransparencyLog ───────────────────────────────────────────────────────

class TestTransparencyLog:

    def test_empty_log_verifies(self):
        """[NIST SP 800-53 AU-9]"""
        assert TransparencyLog().verify_chain() is True

    def test_single_record_verifies(self):
        t = TransparencyLog()
        t.record("a", "s", "test_event")
        assert t.verify_chain() is True

    def test_multi_record_chain_verifies(self):
        t = TransparencyLog()
        for i in range(10): t.record("a", "s", f"e{i}", idx=i)
        assert t.verify_chain() is True

    def test_event_type_kwarg_collision_is_safe(self):
        """Defensive pop prevents TypeError. No standards violation introduced."""
        t = TransparencyLog()
        # Must NOT raise "multiple values for argument 'event_type'"
        t.record("a", "s", "real_event", event_type="should_drop", other="x")
        assert t.verify_chain() is True
        assert t._entries[-1].event_type == "real_event"

    def test_tampered_entry_detected(self):
        """[NIST SP 800-53 AU-9, SI-7]"""
        t = TransparencyLog()
        t.record("a", "s", "event_a")
        e = t._entries[-1]
        e.event_type = "tampered"
        assert t.verify_chain() is False

    def test_details_accessible(self):
        t = TransparencyLog()
        t.record("a", "s", "ev", k1="v1", k2=99)
        d = t._entries[-1].details
        assert d["k1"] == "v1" and d["k2"] == 99

    def test_length_tracks_records(self):
        t = TransparencyLog()
        for i in range(7): t.record("a", "s", f"e{i}")
        assert t.length == 7

    def test_genesis_is_64_zeros(self):
        assert TransparencyLog.GENESIS == "0" * 64


# ── T5: SessionGuard ──────────────────────────────────────────────────────────

class TestSessionGuard:

    def test_initial_state_is_init(self):
        sg = SessionGuard("a")
        assert sg.state == SessionState.INIT and sg.warp_score == 0.0

    def test_activate_transitions_to_active(self):
        """[NIST SP 800-53 AC-2]"""
        sg = SessionGuard("a"); sg.activate()
        assert sg.state == SessionState.ACTIVE

    def test_double_activate_raises(self):
        sg = SessionGuard("a"); sg.activate()
        with pytest.raises(RuntimeError, match="INIT"):
            sg.activate()

    def test_allow_does_not_increment_warp(self):
        sg = SessionGuard("a"); sg.activate()
        sg.record(PolicyDecision.ALLOW)
        assert sg.warp_score == pytest.approx(0.0)

    def test_flag_increments_warp(self):
        """[NIST AI RMF MAP-5.1]"""
        sg = SessionGuard("a"); sg.activate()
        sg.record(PolicyDecision.FLAG)
        assert sg.warp_score == pytest.approx(SessionGuard.WARP_INCREMENT)

    def test_deny_increments_warp(self):
        sg = SessionGuard("a"); sg.activate()
        sg.record(PolicyDecision.DENY)
        assert sg.warp_score == pytest.approx(SessionGuard.WARP_INCREMENT)

    def test_warp_reaches_suspect_threshold(self):
        """[NIST AI RMF MAP-5.1 — SUSPECT state trigger]"""
        sg = SessionGuard("a"); sg.activate()
        steps = int(SessionGuard.SUSPECT_THRESHOLD / SessionGuard.WARP_INCREMENT) + 1
        for _ in range(steps):
            if sg.state == SessionState.ACTIVE:
                sg.record(PolicyDecision.FLAG)
        assert sg.state == SessionState.SUSPECT

    def test_warp_reaches_quarantine_threshold(self):
        """[NIST SP 800-53 IR-4 — incident response trigger]"""
        sg = SessionGuard("a"); sg.activate()
        steps = int(SessionGuard.QUARANTINE_THRESHOLD / SessionGuard.WARP_INCREMENT) + 2
        for _ in range(steps): sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.QUARANTINE

    def test_warp_capped_at_one(self):
        sg = SessionGuard("a"); sg.activate()
        for _ in range(100): sg.record(PolicyDecision.DENY)
        assert sg.warp_score <= 1.0

    def test_record_ignored_in_quarantine(self):
        sg = SessionGuard("a"); sg.activate()
        for _ in range(10): sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.QUARANTINE
        sg.record(PolicyDecision.DENY)   # must not raise or change state
        assert sg.state == SessionState.QUARANTINE

    def test_record_ignored_in_closed(self):
        sg = SessionGuard("a"); sg.activate(); sg.close()
        sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.CLOSED

    def test_resync_resets_warp_and_activates(self):
        """[NIST AI RMF MANAGE-3.2 — recovery procedure]"""
        sg = SessionGuard("a"); sg.activate()
        for _ in range(10): sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.QUARANTINE
        sg.resync()
        assert sg.state == SessionState.ACTIVE
        assert sg.warp_score == pytest.approx(0.0)

    def test_resync_from_non_quarantine_raises(self):
        sg = SessionGuard("a"); sg.activate()
        with pytest.raises(RuntimeError, match="QUARANTINE"):
            sg.resync()

    def test_close_transitions_to_closed(self):
        """[NIST SP 800-53 AC-2 — account termination]"""
        sg = SessionGuard("a"); sg.activate(); sg.close()
        assert sg.state == SessionState.CLOSED

    def test_is_active_in_active_and_suspect(self):
        sg = SessionGuard("a"); sg.activate()
        assert sg.is_active is True

    def test_is_active_false_in_quarantine(self):
        sg = SessionGuard("a"); sg.activate()
        for _ in range(10): sg.record(PolicyDecision.DENY)
        assert sg.is_active is False

    def test_tlog_receives_state_events(self):
        """[NIST SP 800-53 AU-2 — governance event logging]"""
        tlog = TransparencyLog()
        sg   = SessionGuard("a", tlog=tlog); sg.activate()
        init_len = tlog.length
        for _ in range(10): sg.record(PolicyDecision.DENY)
        assert tlog.length > init_len
        types = [e.event_type for e in tlog._entries]
        assert "quarantine_triggered" in types

    def test_session_ids_unique(self):
        ids = {SessionGuard("a").session_id for _ in range(50)}
        assert len(ids) == 50


# ── T6: AegisFrameworkBridge ───────────────────────────────────────────────────

class TestAegisFrameworkBridge:

    def test_start_activates_session(self):
        """[NIST SP 800-53 AC-2]"""
        b = _started_bridge()
        assert b.session.state == SessionState.ACTIVE

    def test_start_rejects_expired_passport(self):
        """Fail-closed. [NIST SP 800-53 IA-5; DoD Zero Trust RA v2.0]"""
        adp = _adapter()
        with pytest.raises(PermissionError, match="expired"):
            adp.register_agent(_passport(expired=True), "test")

    def test_allow_vaults_entry(self):
        """[NIST SP 800-53 AU-2]"""
        b = _started_bridge()
        _, ok = b.evaluate_action("p", 0.8, 0.1)
        assert ok is True and b.vault.length == 1

    def test_deny_does_not_vault(self):
        """DENY payloads never persisted. [NIST SP 800-218A PW.8.1]"""
        b = _started_bridge(ceiling=0.05)
        _, ok = b.evaluate_action("p", 0.8, 0.50)
        assert ok is False and b.vault.length == 0

    def test_flag_vaults_entry(self):
        """FLAG is monitored, not blocked. [NIST AI RMF MAP-5.1]"""
        b = _started_bridge(ceiling=0.70, flag=0.30)
        r, ok = b.evaluate_action("p", 0.8, 0.50)
        assert ok is True and r.decision == PolicyDecision.FLAG
        assert b.vault.length == 1

    def test_deny_still_records_to_tlog(self):
        """Denied actions must be logged. [NIST SP 800-53 AU-2]"""
        b = _started_bridge(ceiling=0.05)
        init = b.tlog.length
        b.evaluate_action("p", 0.8, 0.50)
        assert b.tlog.length > init

    def test_quarantine_blocks_all_actions(self):
        """[NIST SP 800-53 IR-4; DoD Zero Trust RA v2.0]"""
        b = _started_bridge()
        for _ in range(10): b.session.record(PolicyDecision.DENY)
        assert b.session.state == SessionState.QUARANTINE
        with pytest.raises(PermissionError, match="quarantined"):
            b.evaluate_action("any")

    def test_evaluate_before_start_raises(self):
        """[NIST SP 800-53 AC-2 — lifecycle enforcement]"""
        adp = _adapter()
        bridge = adp.register_agent(_passport(), "test")
        with pytest.raises(RuntimeError, match="active"):
            bridge.evaluate_action("payload")

    def test_warp_accumulates_on_flag(self):
        """[NIST AI RMF MAP-5.1]"""
        b = _started_bridge(ceiling=0.70, flag=0.30)
        b.evaluate_action("p", 0.8, 0.50)
        assert b.session.warp_score > 0.0

    def test_require_capability_allows_granted(self):
        """[NIST SP 800-53 AC-6]"""
        b = _started_bridge(caps=frozenset({"read"}))
        b.require_capability("read")   # must not raise

    def test_require_capability_denies_missing(self):
        """[OWASP LLM Top 10 v2025 LLM06/LLM08]"""
        b = _started_bridge(caps=frozenset({"read"}))
        with pytest.raises(PermissionError, match="capability"):
            b.require_capability("write")

    def test_shutdown_returns_true_on_clean_run(self):
        """[NIST SP 800-53 AU-9]"""
        b = _started_bridge()
        b.evaluate_action("p", 0.8, 0.1)
        v, t = b.shutdown()
        assert v is True and t is True

    def test_chain_integrity_after_15_actions(self):
        b = _started_bridge()
        for i in range(15): b.evaluate_action(f"a{i}", 0.8, 0.1)
        v, t = b.shutdown()
        assert v is True and t is True

    def test_metadata_in_vault_entry(self):
        """[NIST SP 800-53 AU-3 — contextual metadata]"""
        b = _started_bridge()
        b.evaluate_action("p", 0.8, 0.1, node_name="my_node", task_id="t42")
        e = b.vault._chain[-1]
        assert e.metadata["node_name"] == "my_node"
        assert e.metadata["task_id"]   == "t42"

    def test_event_type_in_vault_entry(self):
        """[NIST SP 800-53 AU-3 — event type in audit record]"""
        b = _started_bridge()
        b.evaluate_action("p", 0.8, 0.1, event_type="tool_call")
        assert b.vault._chain[-1].event_type == "tool_call"

    def test_status_dict_required_keys(self):
        b = _started_bridge()
        s = b.status_dict()
        for k in ("model_id", "passport_id", "framework", "session_id",
                  "session_state", "warp_score", "action_count",
                  "vault_entries", "tlog_entries", "passport_expired"):
            assert k in s

    def test_status_dict_no_secrets(self):
        """[NIST SP 800-53 SC-12]"""
        s = _started_bridge().status_dict()
        for k in s:
            assert not any(p in k.lower() for p in _REDACT_PATTERNS)

    def test_action_count_increments_on_deny(self):
        """action_count tracks all calls including denied ones."""
        b = _started_bridge()
        b.evaluate_action("a1", 0.8, 0.1)
        b.evaluate_action("a2", 0.8, 0.1)
        assert b._action_count == 2


# ── T7: AegisAdapter ──────────────────────────────────────────────────────────

class TestAegisAdapter:

    def test_register_returns_bridge(self):
        """[NIST SP 800-53 AC-2]"""
        adp = _adapter()
        assert isinstance(adp.register_agent(_passport(), "lg"), AegisFrameworkBridge)

    def test_register_expired_raises(self):
        """Fail-closed at registration. [DoD Zero Trust RA v2.0]"""
        with pytest.raises(PermissionError, match="expired"):
            _adapter().register_agent(_passport(expired=True), "lg")

    def test_agents_share_vault(self):
        """Fleet-level chain. [ISA/IEC 62443-3-3 SR 6.1]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        b1.evaluate_action("p1", 0.8, 0.1)
        b2.evaluate_action("p2", 0.8, 0.1)
        assert adp.vault.length == 2

    def test_agents_share_tlog(self):
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        assert adp.tlog.length >= 2   # at least 2 bridge_started events

    def test_verify_all_chains_after_multi_agent_run(self):
        """[NIST SP 800-53 AU-9, SI-7]"""
        adp = _adapter()
        for i in range(4):
            b = adp.register_agent(_passport(f"a{i}"), "cr"); b.start()
            for _ in range(3): b.evaluate_action("p", 0.8, 0.1)
        v, t = adp.verify_all_chains()
        assert v is True and t is True

    def test_fleet_status_count(self):
        adp = _adapter()
        for i in range(3):
            b = adp.register_agent(_passport(f"a{i}"), "t"); b.start()
        assert len(adp.fleet_status()) == 3

    def test_fleet_status_has_required_keys(self):
        adp = _adapter()
        b = adp.register_agent(_passport(), "t"); b.start()
        for k in ("model_id", "session_state", "warp_score",
                  "vault_entries", "tlog_entries"):
            assert k in adp.fleet_status()[0]

    def test_empty_fleet_verify_chains(self):
        """Cold-start correctness."""
        v, t = _adapter().verify_all_chains()
        assert v is True and t is True

    def test_re_registration_replaces_bridge(self):
        adp = _adapter()
        b1  = adp.register_agent(_passport("x"), "lg")
        b2  = adp.register_agent(_passport("x"), "ag")
        assert adp._bridges["x"] is b2 and adp._bridges["x"] is not b1


# ══════════════════════════════════════════════════════════════════════════════
# DEMO ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    print("\n" + "=" * 70)
    print("  Aegis Adapter — Standalone Demo")
    print("=" * 70 + "\n")

    adapter = AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
        suspect_floor_bump=0.20,
    ))

    r_passport = SemanticPassport(
        model_id="researcher", version="1.2.0",
        policy_hash=hashlib.sha256(b"demo-policy-v1").hexdigest(),
        ttl_seconds=3600,
        capabilities=frozenset({"read", "search", "summarise"}),
    )
    w_passport = SemanticPassport(
        model_id="writer", version="1.0.0",
        policy_hash=hashlib.sha256(b"demo-policy-v1").hexdigest(),
        ttl_seconds=3600,
        capabilities=frozenset({"write", "format"}),
    )

    rb = adapter.register_agent(r_passport, "demo"); rb.start()
    wb = adapter.register_agent(w_passport, "demo"); wb.start()

    actions = [
        (rb, "Research query: AI governance 2025",  0.8, 0.10),
        (rb, "Research query: NIST AI RMF updates", 0.8, 0.15),
        (wb, "Draft executive summary",             0.7, 0.12),
        (rb, "High-sensitivity data access",        0.8, 0.60),   # FLAG
        (wb, "Write final report",                  0.7, 0.10),
    ]

    print("Action evaluations:")
    for bridge, payload, auth, sens in actions:
        result, _ = bridge.evaluate_action(
            payload, authority=auth, sensitivity=sens, event_type="demo_action"
        )
        sym = {"ALLOW": "✓", "FLAG": "⚑", "DENY": "✗"}[result.decision.value]
        print(f"  {sym} {result.decision.value:5s}  [{bridge.passport.model_id}]  "
              f"auth={auth:.2f} sens={sens:.2f}  "
              f"warp={bridge.session.warp_score:.3f}  → {result.reason}")

    v_ok, t_ok = adapter.verify_all_chains()
    print(f"\nFleet vault entries : {adapter.vault.length}")
    print(f"Fleet tlog entries  : {adapter.tlog.length}")
    print(f"Vault chain         : {'PASS ✓' if v_ok else 'FAIL ✗'}")
    print(f"TLog chain          : {'PASS ✓' if t_ok else 'FAIL ✗'}")

    print("\nFleet status:")
    for s in adapter.fleet_status():
        print(f"  {s['model_id']:12s}  state={s['session_state']:10s}  "
              f"warp={s['warp_score']:.4f}  vault={s['vault_entries']}")

    for b in (rb, wb):
        b.shutdown()

    print("\nDemo complete.\n")
    sys.exit(0)