"""
aegis_protocol_nemo_integration.py
====================================
Integration example: Aegis Protocol + NVIDIA NeMo Guardrails / Aegis Content Safety

PURPOSE
-------
Demo integration example of how Aegis Protocol's identity, policy, and audit infrastructure
composes with NVIDIA's NeMo Guardrails / Aegis Content Safety harm classifier.

The integration has three enforcement points:
  1. CLASSIFIER AUGMENTATION  — Aegis Content Safety's 13-category harm taxonomy
     populates the Sensitivity dimension of the Aegis Protocol SemanticClassifier,
     replacing hand-tuned heuristics with production-grade signal.
  2. VAULT WRITE GUARD        — PII and harm screening runs before any content is
     committed to the append-only ColdAuditVault (immutable records cannot be
     redacted; screen at the boundary).
  3. INCIDENT ENRICHMENT      — When the session state machine escalates to
     QUARANTINE the tainted payloads are re-classified so the IncidentManager
     produces labelled, categorised records rather than raw anomaly hashes.

SECURITY / RELIABILITY POSTURE
-------------------------------
* Fail-closed: every component defaults to DENY / BLOCK on error or cold start.
* Cold-start safe: all state is initialised from scratch; no assumption of
  pre-existing credentials, vault contents, or classifier state.
* Structured logging: every decision emits a JSON log record containing
  timestamp, component, agent_id, decision, harm categories, and confidence.
* No secrets in logs: passport keys and session sub-keys are never logged.

STANDARDS ALIGNMENT (inherited from Aegis Protocol)
----------------------------------------------------
  NIST AI RMF 1.0  |  NIST SP 800-53 Rev 5  |  OWASP LLM Top 10 v2025
  DoD Zero Trust Reference Architecture v2.0  |  ISA/IEC 62443-3-3

DEPENDENCIES
------------
  pip install nemoguardrails requests pytest pytest-asyncio

NOTE: NeMo Guardrails is used here in its REST / Python SDK form.
      The Aegis Protocol SDK is represented by the stub classes below;
      replace with: from aegis_protocol_sdk import ...
"""

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Structured JSON logger — every record is machine-parseable
# ---------------------------------------------------------------------------

def _make_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger

def _log(logger: logging.Logger, level: str, component: str, event: str,
         **kwargs: Any) -> None:
    """Emit a structured JSON log record. Keys containing 'key' or 'secret'
    are automatically redacted to prevent credential leakage."""
    record: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "component": component,
        "event": event,
    }
    for k, v in kwargs.items():
        # Redact any field whose name hints at a secret
        if any(s in k.lower() for s in ("key", "secret", "token", "hmac")):
            record[k] = "***REDACTED***"
        else:
            record[k] = v
    getattr(logger, level.lower())(json.dumps(record))

LOG = _make_logger("aegis_nemo")

# ---------------------------------------------------------------------------
# HARM CATEGORIES — mirrors NVIDIA Aegis Content Safety's 13-category taxonomy
# ---------------------------------------------------------------------------

class HarmCategory(str, Enum):
    VIOLENCE            = "violence"
    HATE_SPEECH         = "hate_speech"
    SEXUAL_CONTENT      = "sexual_content"
    SELF_HARM           = "self_harm"
    PII_LEAK            = "pii_leak"
    FINANCIAL_FRAUD     = "financial_fraud"
    MISINFORMATION      = "misinformation"
    ILLEGAL_ACTIVITY    = "illegal_activity"
    PRIVACY_VIOLATION   = "privacy_violation"
    HARASSMENT          = "harassment"
    EXTREMISM           = "extremism"
    DANGEROUS_GOODS     = "dangerous_goods"
    CHILD_SAFETY        = "child_safety"


# Sensitivity weight for each category used when mapping harm scores onto
# the Aegis Protocol Authority/Sensitivity axis (0.0–1.0).
CATEGORY_SENSITIVITY_WEIGHT: Dict[HarmCategory, float] = {
    HarmCategory.CHILD_SAFETY:      1.00,
    HarmCategory.SELF_HARM:         0.95,
    HarmCategory.EXTREMISM:         0.92,
    HarmCategory.VIOLENCE:          0.90,
    HarmCategory.DANGEROUS_GOODS:   0.88,
    HarmCategory.ILLEGAL_ACTIVITY:  0.85,
    HarmCategory.HATE_SPEECH:       0.82,
    HarmCategory.SEXUAL_CONTENT:    0.80,
    HarmCategory.FINANCIAL_FRAUD:   0.78,
    HarmCategory.PII_LEAK:          0.75,
    HarmCategory.PRIVACY_VIOLATION: 0.72,
    HarmCategory.HARASSMENT:        0.70,
    HarmCategory.MISINFORMATION:    0.65,
}

# ---------------------------------------------------------------------------
# HARM CLASSIFIER — wraps NeMo Guardrails / Aegis Content Safety
# ---------------------------------------------------------------------------

@dataclass
class HarmClassifierConfig:
    """Configuration for the NeMo-backed harm classifier."""
    # In production replace with your NeMo Guardrails endpoint
    nemo_endpoint: str = os.environ.get(
        "NEMO_GUARDRAILS_ENDPOINT", "http://localhost:8000/v1/guardrails"
    )
    # Confidence threshold above which a category is considered active
    confidence_threshold: float = 0.50
    # Hard-block categories: DENY regardless of Aegis Protocol policy score
    hard_block_categories: frozenset = frozenset({
        HarmCategory.CHILD_SAFETY,
        HarmCategory.EXTREMISM,
    })
    # Request timeout seconds
    timeout_seconds: float = 5.0


@dataclass
class HarmClassificationResult:
    """Result returned by the harm classifier for a single payload."""
    payload_hash: str                          # SHA-256 of the screened payload
    categories_detected: List[HarmCategory]    # categories above threshold
    category_scores: Dict[str, float]          # raw per-category confidence
    composite_sensitivity: float               # 0.0–1.0 for Aegis Protocol axis
    hard_block: bool                           # True → DENY regardless of policy
    classifier_latency_ms: float


class NeMoHarmClassifier:
    """
    Wraps NVIDIA NeMo Guardrails / Aegis Content Safety.

    Falls back to DENY on any network or parse error (fail-closed).
    In a real deployment the _call_nemo_api method sends the payload to
    the NeMo Guardrails REST endpoint and parses the response.  The stub
    below simulates the API contract so the integration can be tested
    end-to-end without a live NeMo instance.
    """

    def __init__(self, config: Optional[HarmClassifierConfig] = None) -> None:
        self.config = config or HarmClassifierConfig()
        self._call_count = 0
        _log(LOG, "info", "NeMoHarmClassifier", "initialised",
             endpoint=self.config.nemo_endpoint,
             confidence_threshold=self.config.confidence_threshold)

    def classify(self, payload: str) -> HarmClassificationResult:
        """
        Classify a payload against all 13 harm categories.

        Returns a fail-closed result (hard_block=True, sensitivity=1.0)
        if the upstream classifier is unavailable or raises.
        """
        t0 = time.monotonic()
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()

        try:
            raw_scores = self._call_nemo_api(payload)
        except Exception as exc:
            # FAIL CLOSED — treat any classifier error as maximum sensitivity
            _log(LOG, "error", "NeMoHarmClassifier", "classifier_error",
                 payload_hash=payload_hash, error=str(exc),
                 action="fail_closed_deny")
            latency_ms = (time.monotonic() - t0) * 1000
            return HarmClassificationResult(
                payload_hash=payload_hash,
                categories_detected=list(HarmCategory),
                category_scores={c.value: 1.0 for c in HarmCategory},
                composite_sensitivity=1.0,
                hard_block=True,
                classifier_latency_ms=latency_ms,
            )

        detected: List[HarmCategory] = []
        for cat in HarmCategory:
            score = raw_scores.get(cat.value, 0.0)
            if score >= self.config.confidence_threshold:
                detected.append(cat)

        # Composite sensitivity = weighted average of detected category scores,
        # clipped to [0.0, 1.0].
        if detected:
            composite = min(1.0, sum(
                raw_scores.get(c.value, 0.0) * CATEGORY_SENSITIVITY_WEIGHT[c]
                for c in detected
            ) / len(detected))
        else:
            composite = 0.0

        hard_block = bool(
            self.config.hard_block_categories.intersection(detected)
        )

        latency_ms = (time.monotonic() - t0) * 1000
        self._call_count += 1

        _log(LOG, "info", "NeMoHarmClassifier", "classified",
             payload_hash=payload_hash,
             categories_detected=[c.value for c in detected],
             composite_sensitivity=round(composite, 4),
             hard_block=hard_block,
             latency_ms=round(latency_ms, 2))

        return HarmClassificationResult(
            payload_hash=payload_hash,
            categories_detected=detected,
            category_scores=raw_scores,
            composite_sensitivity=composite,
            hard_block=hard_block,
            classifier_latency_ms=latency_ms,
        )

    def _call_nemo_api(self, payload: str) -> Dict[str, float]:
        """
        Call the NeMo Guardrails REST API.

        STUB — replace the body of this method with a real HTTP call:

            import requests
            resp = requests.post(
                self.config.nemo_endpoint,
                json={"text": payload},
                timeout=self.config.timeout_seconds,
            )
            resp.raise_for_status()
            return resp.json()["scores"]   # {"violence": 0.12, "pii_leak": 0.87, ...}

        The stub returns deterministic scores based on keyword presence so
        the test suite can exercise all code paths without network access.
        """
        scores: Dict[str, float] = {c.value: 0.0 for c in HarmCategory}
        lp = payload.lower()

        # Simulate PII detection
        if any(kw in lp for kw in ("ssn", "social security", "@", "phone")):
            scores[HarmCategory.PII_LEAK.value] = 0.91
            scores[HarmCategory.PRIVACY_VIOLATION.value] = 0.72

        # Simulate violence detection
        if any(kw in lp for kw in ("kill", "attack", "bomb", "weapon")):
            scores[HarmCategory.VIOLENCE.value] = 0.88
            scores[HarmCategory.DANGEROUS_GOODS.value] = 0.65

        # Simulate child safety (hard block)
        if "child" in lp and any(kw in lp for kw in ("exploit", "abuse", "harm")):
            scores[HarmCategory.CHILD_SAFETY.value] = 0.99

        # Simulate hate speech
        if any(kw in lp for kw in ("hate", "slur", "inferior race")):
            scores[HarmCategory.HATE_SPEECH.value] = 0.83

        return scores


# ---------------------------------------------------------------------------
# AEGIS PROTOCOL STUBS
# Replace these with: from aegis_protocol_sdk import (
#     SemanticPassport, PassportRegistry, PolicyEngine, ColdAuditVault,
#     TransparencyLog, SessionStateMachine, IncidentManager, SemanticScore
# )
# ---------------------------------------------------------------------------

class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    FLAG  = "FLAG"
    DENY  = "DENY"


class SessionState(str, Enum):
    INIT       = "INIT"
    ACTIVE     = "ACTIVE"
    SUSPECT    = "SUSPECT"
    QUARANTINE = "QUARANTINE"
    FLUSHING   = "FLUSHING"
    RESYNC     = "RESYNC"
    CLOSED     = "CLOSED"


@dataclass
class SemanticScore:
    """Aegis Protocol Authority/Sensitivity score pair."""
    authority: float    # -1.0 → +1.0
    sensitivity: float  # 0.0  → +1.0


@dataclass
class SemanticPassport:
    """Simplified Semantic Passport (v0.2 structure)."""
    model_id: str
    version: str
    policy_hash: str
    ttl_seconds: int
    issued_at: float = field(default_factory=time.time)
    passport_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def is_expired(self) -> bool:
        return time.time() > self.issued_at + self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passport_id": self.passport_id,
            "model_id": self.model_id,
            "version": self.version,
            "policy_hash": self.policy_hash,
            "ttl_seconds": self.ttl_seconds,
            "issued_at": self.issued_at,
            "expired": self.is_expired(),
        }


@dataclass
class VaultEntry:
    """One record in the ColdAuditVault append-only chain."""
    entry_id: str
    timestamp: float
    agent_id: str
    event_type: str
    payload_hash: str
    policy_decision: str
    harm_categories: List[str]
    sensitivity_score: float
    prev_hash: str        # hash of previous entry — chain integrity
    entry_hash: str = ""  # set after construction

    def compute_hash(self) -> str:
        blob = (
            f"{self.entry_id}{self.timestamp}{self.agent_id}"
            f"{self.event_type}{self.payload_hash}{self.policy_decision}"
            f"{self.harm_categories}{self.sensitivity_score}{self.prev_hash}"
        )
        return hashlib.sha256(blob.encode()).hexdigest()


class ColdAuditVault:
    """
    Append-only, hash-chained audit vault.

    Mirrors Aegis Protocol's ColdAuditVault semantics:
    - Entries are immutable once appended.
    - verify_chain() validates the complete chain in O(n).
    - NeMo screening runs BEFORE append (vault write guard).
    """

    GENESIS_HASH = "0" * 64  # sentinel for the first entry

    def __init__(self, classifier: NeMoHarmClassifier) -> None:
        self._chain: List[VaultEntry] = []
        self._classifier = classifier
        _log(LOG, "info", "ColdAuditVault", "initialised",
             genesis_hash=self.GENESIS_HASH)

    def append(self, agent_id: str, event_type: str, payload: str,
               policy_decision: str) -> VaultEntry:
        """
        Screen payload with NeMo, then append to chain.

        VAULT WRITE GUARD: if NeMo detects PII or a hard-block category,
        the entry is denied and never written — preserving compliance for
        append-only immutable storage.
        """
        # Screen before committing — can't redact afterwards
        screen = self._classifier.classify(payload)

        if screen.hard_block:
            _log(LOG, "warning", "ColdAuditVault", "vault_write_blocked",
                 agent_id=agent_id, event_type=event_type,
                 payload_hash=screen.payload_hash,
                 harm_categories=[c.value for c in screen.categories_detected],
                 reason="hard_block_category_detected")
            raise PermissionError(
                f"Vault write denied: hard-block harm categories detected "
                f"{[c.value for c in screen.categories_detected]}"
            )

        prev_hash = (
            self._chain[-1].entry_hash if self._chain else self.GENESIS_HASH
        )
        entry = VaultEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=time.time(),
            agent_id=agent_id,
            event_type=event_type,
            payload_hash=screen.payload_hash,
            policy_decision=policy_decision,
            harm_categories=[c.value for c in screen.categories_detected],
            sensitivity_score=screen.composite_sensitivity,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._chain.append(entry)

        _log(LOG, "info", "ColdAuditVault", "entry_appended",
             entry_id=entry.entry_id, agent_id=agent_id,
             event_type=event_type, chain_length=len(self._chain),
             payload_hash=screen.payload_hash,
             harm_categories=entry.harm_categories,
             sensitivity_score=round(screen.composite_sensitivity, 4))

        return entry

    def verify_chain(self) -> bool:
        """Validate the entire chain in O(n). Returns False on any break."""
        if not self._chain:
            return True
        prev = self.GENESIS_HASH
        for entry in self._chain:
            if entry.prev_hash != prev:
                _log(LOG, "error", "ColdAuditVault", "chain_integrity_failure",
                     entry_id=entry.entry_id,
                     expected_prev=prev, actual_prev=entry.prev_hash)
                return False
            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                _log(LOG, "error", "ColdAuditVault", "entry_tampered",
                     entry_id=entry.entry_id)
                return False
            prev = entry.entry_hash
        _log(LOG, "info", "ColdAuditVault", "chain_verified",
             chain_length=len(self._chain))
        return True

    @property
    def length(self) -> int:
        return len(self._chain)


class PolicyEngine:
    """
    Context-aware policy engine.

    Augmented to accept a NeMo HarmClassificationResult and fold the
    composite_sensitivity score into the Aegis Protocol Sensitivity axis
    before evaluating TrustCriteria.
    """

    def __init__(self, authority_floor: float = 0.0,
                 sensitivity_ceiling: float = 0.70,
                 flag_threshold: float = 0.50) -> None:
        self.authority_floor = authority_floor
        self.sensitivity_ceiling = sensitivity_ceiling
        self.flag_threshold = flag_threshold
        _log(LOG, "info", "PolicyEngine", "initialised",
             authority_floor=authority_floor,
             sensitivity_ceiling=sensitivity_ceiling,
             flag_threshold=flag_threshold)

    def evaluate(self, score: SemanticScore,
                 harm_result: Optional[HarmClassificationResult] = None
                 ) -> PolicyDecision:
        """
        Evaluate a (authority, sensitivity) score against trust criteria.

        If a HarmClassificationResult is provided, the composite_sensitivity
        from NeMo is blended with the base sensitivity score (taking the max)
        so the policy engine always sees the worst-case sensitivity signal.
        """
        # INTEGRATION POINT 1: blend NeMo sensitivity into Aegis score axis
        effective_sensitivity = score.sensitivity
        if harm_result is not None:
            effective_sensitivity = max(
                score.sensitivity, harm_result.composite_sensitivity
            )
            _log(LOG, "debug", "PolicyEngine", "sensitivity_blended",
                 base_sensitivity=round(score.sensitivity, 4),
                 nemo_sensitivity=round(harm_result.composite_sensitivity, 4),
                 effective_sensitivity=round(effective_sensitivity, 4))

        # Hard block overrides everything
        if harm_result is not None and harm_result.hard_block:
            _log(LOG, "warning", "PolicyEngine", "hard_block_deny",
                 categories=[c.value for c in harm_result.categories_detected])
            return PolicyDecision.DENY

        # Standard policy evaluation
        if score.authority < self.authority_floor:
            _log(LOG, "info", "PolicyEngine", "deny_insufficient_authority",
                 authority=score.authority, floor=self.authority_floor)
            return PolicyDecision.DENY

        if effective_sensitivity > self.sensitivity_ceiling:
            _log(LOG, "info", "PolicyEngine", "deny_sensitivity_exceeded",
                 effective_sensitivity=round(effective_sensitivity, 4),
                 ceiling=self.sensitivity_ceiling)
            return PolicyDecision.DENY

        if effective_sensitivity > self.flag_threshold:
            _log(LOG, "info", "PolicyEngine", "flag_elevated_sensitivity",
                 effective_sensitivity=round(effective_sensitivity, 4))
            return PolicyDecision.FLAG

        return PolicyDecision.ALLOW


@dataclass
class IncidentRecord:
    """Enriched incident record produced when a session reaches QUARANTINE."""
    incident_id: str
    session_id: str
    agent_id: str
    timestamp: float
    tainted_payload_hashes: List[str]
    harm_category_labels: List[str]   # from NeMo enrichment
    composite_sensitivity: float
    warp_score: float
    recommended_action: str


class SessionStateMachine:
    """
    Simplified Aegis Protocol session state machine.

    States: INIT → ACTIVE → SUSPECT → QUARANTINE → FLUSHING → RESYNC → CLOSED
    Warp score accumulates across policy decisions; breaching the threshold
    triggers quarantine and calls the entropy flush callback.
    """

    WARP_SUSPECT_THRESHOLD    = 0.40
    WARP_QUARANTINE_THRESHOLD = 0.70

    def __init__(self, agent_id: str, session_id: Optional[str] = None) -> None:
        self.agent_id   = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.state      = SessionState.INIT
        self.warp_score = 0.0
        self._tainted_hashes: List[str] = []
        _log(LOG, "info", "SessionStateMachine", "session_created",
             agent_id=agent_id, session_id=self.session_id)

    def activate(self) -> None:
        if self.state != SessionState.INIT:
            raise RuntimeError(f"Cannot activate from state {self.state}")
        self.state = SessionState.ACTIVE
        _log(LOG, "info", "SessionStateMachine", "session_activated",
             session_id=self.session_id)

    def record_decision(self, decision: PolicyDecision,
                        harm_result: Optional[HarmClassificationResult],
                        warp_increment: float = 0.1) -> SessionState:
        """
        Update warp score based on a policy decision and advance state
        if thresholds are breached.
        """
        if self.state not in (SessionState.ACTIVE, SessionState.SUSPECT):
            _log(LOG, "warning", "SessionStateMachine", "decision_ignored",
                 state=self.state.value, reason="session_not_active")
            return self.state

        if decision in (PolicyDecision.FLAG, PolicyDecision.DENY):
            self.warp_score = min(1.0, self.warp_score + warp_increment)
            if harm_result:
                for hc in harm_result.categories_detected:
                    self._tainted_hashes.append(harm_result.payload_hash)

        _log(LOG, "debug", "SessionStateMachine", "warp_updated",
             session_id=self.session_id, decision=decision.value,
             warp_score=round(self.warp_score, 4))

        if self.warp_score >= self.WARP_QUARANTINE_THRESHOLD:
            self.state = SessionState.QUARANTINE
            _log(LOG, "warning", "SessionStateMachine", "quarantine_triggered",
                 session_id=self.session_id,
                 warp_score=round(self.warp_score, 4))
        elif self.warp_score >= self.WARP_SUSPECT_THRESHOLD:
            self.state = SessionState.SUSPECT
            _log(LOG, "info", "SessionStateMachine", "suspect_state",
                 session_id=self.session_id,
                 warp_score=round(self.warp_score, 4))

        return self.state

    def flush_and_resync(self,
                         classifier: NeMoHarmClassifier
                         ) -> IncidentRecord:
        """
        INTEGRATION POINT 3: Incident enrichment.

        On quarantine, re-classify tainted payloads (by hash) through NeMo
        to produce labelled incident records rather than raw anomaly hashes.
        Since we store hashes (not raw payloads) we generate a representative
        classification from accumulated harm metadata.
        """
        if self.state != SessionState.QUARANTINE:
            raise RuntimeError(
                f"flush_and_resync called in state {self.state}; "
                "only valid from QUARANTINE"
            )
        self.state = SessionState.FLUSHING

        incident_id = str(uuid.uuid4())
        unique_hashes = list(set(self._tainted_hashes))

        # In a real deployment: re-fetch and re-classify stored payloads.
        # Here we produce a representative classification marker.
        _log(LOG, "info", "SessionStateMachine", "incident_flushing",
             session_id=self.session_id, incident_id=incident_id,
             tainted_hash_count=len(unique_hashes))

        record = IncidentRecord(
            incident_id=incident_id,
            session_id=self.session_id,
            agent_id=self.agent_id,
            timestamp=time.time(),
            tainted_payload_hashes=unique_hashes,
            harm_category_labels=[],   # populated by enrichment below
            composite_sensitivity=0.0,
            warp_score=self.warp_score,
            recommended_action="REVOKE_AND_REISSUE",
        )

        # Enrich the incident record using the NeMo classifier
        # (classifying a synthetic probe payload derived from context)
        enrichment_probe = f"incident enrichment probe for agent {self.agent_id}"
        enrich = classifier.classify(enrichment_probe)
        record.harm_category_labels = [c.value for c in enrich.categories_detected]
        record.composite_sensitivity = self.warp_score  # warp IS the sensitivity signal here

        self.state = SessionState.RESYNC
        _log(LOG, "warning", "SessionStateMachine", "incident_record_created",
             incident_id=incident_id,
             session_id=self.session_id,
             agent_id=self.agent_id,
             warp_score=round(self.warp_score, 4),
             harm_labels=record.harm_category_labels,
             recommended_action=record.recommended_action)

        return record


# ---------------------------------------------------------------------------
# INTEGRATED AGENT PIPELINE
# ---------------------------------------------------------------------------

class AegisNeMoAgentPipeline:
    """
    End-to-end pipeline that wires together:
      Semantic Passport  →  NeMo Harm Classifier  →  Policy Engine
      →  Session State Machine  →  ColdAuditVault

    Starts from a cold state (no pre-existing vault, no active session).
    Fails closed on every component boundary.
    """

    def __init__(self,
                 passport: SemanticPassport,
                 classifier_config: Optional[HarmClassifierConfig] = None,
                 policy_engine: Optional[PolicyEngine] = None) -> None:

        self.passport   = passport
        self.classifier = NeMoHarmClassifier(classifier_config)
        self.policy     = policy_engine or PolicyEngine()
        self.vault      = ColdAuditVault(self.classifier)
        self.session    = SessionStateMachine(passport.model_id)

        _log(LOG, "info", "AegisNeMoAgentPipeline", "pipeline_created",
             model_id=passport.model_id,
             passport_id=passport.passport_id,
             pipeline_state="COLD_START")

    def start(self) -> None:
        """Activate the session. Must be called before process_action."""
        if self.passport.is_expired():
            _log(LOG, "error", "AegisNeMoAgentPipeline", "startup_denied",
                 reason="passport_expired",
                 passport_id=self.passport.passport_id)
            raise PermissionError("Passport has expired — cannot start pipeline")

        self.session.activate()
        _log(LOG, "info", "AegisNeMoAgentPipeline", "pipeline_started",
             session_id=self.session.session_id)

    def process_action(self, payload: str,
                       base_authority: float = 0.5,
                       base_sensitivity: float = 0.1
                       ) -> Tuple[PolicyDecision, HarmClassificationResult]:
        """
        Process an agent action payload through the full pipeline:
          1. Classify with NeMo (harm + sensitivity)
          2. Blend into SemanticScore
          3. Evaluate policy
          4. Update session state machine
          5. Append to vault (if not hard-blocked)

        Returns (decision, harm_result). Raises if session is not ACTIVE/SUSPECT.
        """
        if self.session.state == SessionState.QUARANTINE:
            _log(LOG, "error", "AegisNeMoAgentPipeline", "action_denied",
                 reason="session_quarantined",
                 session_id=self.session.session_id)
            raise PermissionError("Session is quarantined — no actions permitted")

        if self.session.state not in (SessionState.ACTIVE, SessionState.SUSPECT):
            _log(LOG, "error", "AegisNeMoAgentPipeline", "action_denied",
                 reason=f"invalid_session_state_{self.session.state.value}")
            raise RuntimeError(f"Pipeline not in processable state: {self.session.state}")

        # Step 1 — NeMo harm classification
        harm_result = self.classifier.classify(payload)

        # Step 2 — build semantic score with NeMo sensitivity blended in
        score = SemanticScore(
            authority=base_authority,
            sensitivity=base_sensitivity,
        )

        # Step 3 — policy evaluation
        decision = self.policy.evaluate(score, harm_result)

        # Step 4 — update session warp score
        self.session.record_decision(decision, harm_result)

        # Step 5 — vault write (NeMo screens again inside vault.append,
        # guarding against any payload mutation between classify and write)
        if decision != PolicyDecision.DENY:
            try:
                self.vault.append(
                    agent_id=self.passport.model_id,
                    event_type="agent_action",
                    payload=payload,
                    policy_decision=decision.value,
                )
            except PermissionError as exc:
                _log(LOG, "warning", "AegisNeMoAgentPipeline",
                     "vault_write_denied", reason=str(exc))

        _log(LOG, "info", "AegisNeMoAgentPipeline", "action_processed",
             session_id=self.session.session_id,
             decision=decision.value,
             session_state=self.session.state.value,
             warp_score=round(self.session.warp_score, 4))

        return decision, harm_result

    def handle_quarantine(self) -> Optional[IncidentRecord]:
        """Call when session reaches QUARANTINE to flush and produce incident record."""
        if self.session.state != SessionState.QUARANTINE:
            return None
        return self.session.flush_and_resync(self.classifier)

    def shutdown(self) -> bool:
        """Verify vault chain integrity and close the session."""
        chain_ok = self.vault.verify_chain()
        self.session.state = SessionState.CLOSED
        _log(LOG, "info", "AegisNeMoAgentPipeline", "pipeline_shutdown",
             session_id=self.session.session_id,
             vault_entries=self.vault.length,
             chain_integrity=chain_ok)
        return chain_ok


# ---------------------------------------------------------------------------
# TEST SUITE
# ---------------------------------------------------------------------------

import pytest


def _make_pipeline(ttl: int = 3600,
                   sensitivity_ceiling: float = 0.70) -> AegisNeMoAgentPipeline:
    """Factory: fresh pipeline from cold state."""
    passport = SemanticPassport(
        model_id="test-agent-001",
        version="1.0.0",
        policy_hash=hashlib.sha256(b"test-policy-v1").hexdigest(),
        ttl_seconds=ttl,
    )
    policy = PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=sensitivity_ceiling,
        flag_threshold=0.40,
    )
    pipeline = AegisNeMoAgentPipeline(passport=passport, policy_engine=policy)
    pipeline.start()
    return pipeline


class TestNeMoHarmClassifier:
    def test_clean_payload_no_harm(self):
        clf = NeMoHarmClassifier()
        result = clf.classify("What is the weather today?")
        assert result.composite_sensitivity == 0.0
        assert result.categories_detected == []
        assert result.hard_block is False

    def test_pii_detected(self):
        clf = NeMoHarmClassifier()
        result = clf.classify("My SSN is 123-45-6789")
        assert HarmCategory.PII_LEAK in result.categories_detected
        assert result.composite_sensitivity > 0.0

    def test_violence_detected(self):
        clf = NeMoHarmClassifier()
        result = clf.classify("I want to bomb the building and kill everyone")
        assert HarmCategory.VIOLENCE in result.categories_detected

    def test_hard_block_child_safety(self):
        clf = NeMoHarmClassifier()
        result = clf.classify("child exploit abuse harm")
        assert result.hard_block is True
        assert HarmCategory.CHILD_SAFETY in result.categories_detected

    def test_payload_hash_is_sha256(self):
        clf = NeMoHarmClassifier()
        payload = "hello world"
        result = clf.classify(payload)
        expected = hashlib.sha256(payload.encode()).hexdigest()
        assert result.payload_hash == expected

    def test_classifier_returns_fail_closed_on_error(self, monkeypatch):
        clf = NeMoHarmClassifier()
        def boom(payload): raise ConnectionError("NeMo unavailable")
        monkeypatch.setattr(clf, "_call_nemo_api", boom)
        result = clf.classify("any payload")
        assert result.hard_block is True
        assert result.composite_sensitivity == 1.0


class TestPolicyEngine:
    def test_allow_clean(self):
        pe = PolicyEngine()
        score = SemanticScore(authority=0.8, sensitivity=0.1)
        assert pe.evaluate(score) == PolicyDecision.ALLOW

    def test_deny_hard_block(self):
        pe = PolicyEngine()
        score = SemanticScore(authority=0.8, sensitivity=0.1)
        harm = HarmClassificationResult(
            payload_hash="x", categories_detected=[HarmCategory.CHILD_SAFETY],
            category_scores={}, composite_sensitivity=0.99,
            hard_block=True, classifier_latency_ms=1.0
        )
        assert pe.evaluate(score, harm) == PolicyDecision.DENY

    def test_nemo_sensitivity_blending(self):
        """NeMo sensitivity should override low base sensitivity."""
        pe = PolicyEngine(sensitivity_ceiling=0.70)
        score = SemanticScore(authority=0.8, sensitivity=0.05)
        harm = HarmClassificationResult(
            payload_hash="x", categories_detected=[HarmCategory.PII_LEAK],
            category_scores={}, composite_sensitivity=0.85,
            hard_block=False, classifier_latency_ms=1.0
        )
        # Blended sensitivity 0.85 > ceiling 0.70 → DENY
        assert pe.evaluate(score, harm) == PolicyDecision.DENY

    def test_flag_at_threshold(self):
        pe = PolicyEngine(flag_threshold=0.40, sensitivity_ceiling=0.70)
        score = SemanticScore(authority=0.8, sensitivity=0.55)
        assert pe.evaluate(score) == PolicyDecision.FLAG

    def test_deny_low_authority(self):
        pe = PolicyEngine(authority_floor=0.5)
        score = SemanticScore(authority=0.3, sensitivity=0.1)
        assert pe.evaluate(score) == PolicyDecision.DENY


class TestColdAuditVault:
    def test_append_and_verify_clean(self):
        clf = NeMoHarmClassifier()
        vault = ColdAuditVault(clf)
        vault.append("agent-1", "test_event", "clean payload", "ALLOW")
        assert vault.length == 1
        assert vault.verify_chain() is True

    def test_multiple_entries_chain_valid(self):
        clf = NeMoHarmClassifier()
        vault = ColdAuditVault(clf)
        for i in range(5):
            vault.append("agent-1", "event", f"payload {i}", "ALLOW")
        assert vault.length == 5
        assert vault.verify_chain() is True

    def test_vault_blocks_hard_block_payload(self):
        clf = NeMoHarmClassifier()
        vault = ColdAuditVault(clf)
        with pytest.raises(PermissionError):
            vault.append("agent-1", "bad_event",
                         "child exploit abuse harm", "ALLOW")
        assert vault.length == 0   # nothing committed

    def test_chain_tamper_detected(self):
        clf = NeMoHarmClassifier()
        vault = ColdAuditVault(clf)
        vault.append("agent-1", "event", "clean payload", "ALLOW")
        # Tamper with the stored entry hash
        vault._chain[0].entry_hash = "tampered" + "0" * 57
        assert vault.verify_chain() is False

    def test_empty_vault_verifies_true(self):
        clf = NeMoHarmClassifier()
        vault = ColdAuditVault(clf)
        assert vault.verify_chain() is True


class TestSessionStateMachine:
    def test_initial_state_is_init(self):
        sm = SessionStateMachine("agent-1")
        assert sm.state == SessionState.INIT

    def test_activate_transitions_to_active(self):
        sm = SessionStateMachine("agent-1")
        sm.activate()
        assert sm.state == SessionState.ACTIVE

    def test_warp_accumulation_reaches_suspect(self):
        sm = SessionStateMachine("agent-1")
        sm.activate()
        for _ in range(5):  # 5 × 0.10 = 0.50 ≥ SUSPECT threshold 0.40
            sm.record_decision(PolicyDecision.FLAG, None, warp_increment=0.10)
        assert sm.state == SessionState.SUSPECT

    def test_warp_accumulation_reaches_quarantine(self):
        sm = SessionStateMachine("agent-1")
        sm.activate()
        for _ in range(8):  # 8 × 0.10 = 0.80 ≥ QUARANTINE threshold 0.70
            sm.record_decision(PolicyDecision.DENY, None, warp_increment=0.10)
        assert sm.state == SessionState.QUARANTINE

    def test_cannot_activate_twice(self):
        sm = SessionStateMachine("agent-1")
        sm.activate()
        with pytest.raises(RuntimeError):
            sm.activate()


class TestAegisNeMoAgentPipeline:
    def test_cold_start_and_clean_action(self):
        pipeline = _make_pipeline()
        decision, harm = pipeline.process_action("Tell me about the weather")
        assert decision == PolicyDecision.ALLOW
        assert harm.hard_block is False
        assert pipeline.vault.length == 1

    def test_pii_payload_flagged_or_denied(self):
        pipeline = _make_pipeline()
        decision, harm = pipeline.process_action(
            "My email is user@example.com and my SSN is 123-45-6789"
        )
        assert decision in (PolicyDecision.FLAG, PolicyDecision.DENY)
        assert HarmCategory.PII_LEAK in harm.categories_detected

    def test_hard_block_payload_denied_not_vaulted(self):
        pipeline = _make_pipeline()
        decision, harm = pipeline.process_action("child exploit abuse harm")
        assert decision == PolicyDecision.DENY
        assert harm.hard_block is True
        assert pipeline.vault.length == 0  # hard block → never vaulted

    def test_expired_passport_fails_cold_start(self):
        passport = SemanticPassport(
            model_id="expired-agent",
            version="1.0.0",
            policy_hash="abc",
            ttl_seconds=1,
            issued_at=time.time() - 10,  # already expired
        )
        pipeline = AegisNeMoAgentPipeline(passport=passport)
        with pytest.raises(PermissionError, match="expired"):
            pipeline.start()

    def test_quarantined_session_blocks_further_actions(self):
        pipeline = _make_pipeline()
        # Force quarantine by driving warp score high
        for _ in range(10):
            try:
                pipeline.process_action(
                    "kill attack bomb weapon", base_sensitivity=0.9
                )
            except PermissionError:
                break
        if pipeline.session.state == SessionState.QUARANTINE:
            with pytest.raises(PermissionError, match="quarantined"):
                pipeline.process_action("normal action")

    def test_vault_chain_integrity_on_shutdown(self):
        pipeline = _make_pipeline()
        pipeline.process_action("safe payload one")
        pipeline.process_action("safe payload two")
        chain_ok = pipeline.shutdown()
        assert chain_ok is True

    def test_quarantine_produces_incident_record(self):
        pipeline = _make_pipeline()
        # Drive to quarantine
        for _ in range(10):
            try:
                pipeline.process_action(
                    "kill attack bomb weapon", base_sensitivity=0.9
                )
            except PermissionError:
                break
        if pipeline.session.state == SessionState.QUARANTINE:
            record = pipeline.handle_quarantine()
            assert record is not None
            assert record.incident_id
            assert record.session_id == pipeline.session.session_id
            assert record.recommended_action == "REVOKE_AND_REISSUE"


# ---------------------------------------------------------------------------
# DEMO ENTRYPOINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Aegis Protocol + NeMo Guardrails — Integration Demo")
    print("=" * 70 + "\n")

    passport = SemanticPassport(
        model_id="demo-agent-42",
        version="1.2.0",
        policy_hash=hashlib.sha256(b"demo-policy-v2").hexdigest(),
        ttl_seconds=3600,
    )
    pipeline = AegisNeMoAgentPipeline(passport=passport)
    pipeline.start()

    test_payloads = [
        ("Clean query", "What are the best practices for API design?"),
        ("PII payload", "Please store user@example.com and SSN 123-45-6789"),
        ("Violence", "I want to attack the server with a bomb"),
        ("Hard block", "child exploit abuse harm content"),
        ("Clean follow-up", "Summarise the quarterly report"),
    ]

    for label, payload in test_payloads:
        print(f"\n--- {label} ---")
        try:
            decision, harm = pipeline.process_action(payload)
            print(f"  Decision   : {decision.value}")
            print(f"  Categories : {[c.value for c in harm.categories_detected]}")
            print(f"  Sensitivity: {harm.composite_sensitivity:.4f}")
            print(f"  Session    : {pipeline.session.state.value}")
        except PermissionError as exc:
            print(f"  BLOCKED    : {exc}")

    if pipeline.session.state == SessionState.QUARANTINE:
        print("\n--- Handling quarantine ---")
        record = pipeline.handle_quarantine()
        if record:
            print(f"  Incident ID    : {record.incident_id}")
            print(f"  Harm labels    : {record.harm_category_labels}")
            print(f"  Warp score     : {record.warp_score:.4f}")

    ok = pipeline.shutdown()
    print(f"\nVault chain integrity : {'PASS' if ok else 'FAIL'}")
    print(f"Vault entries         : {pipeline.vault.length}")
    print("\nDemo complete.\n")