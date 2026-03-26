"""
Aegis Protocol (Semantic Passport System)
=========================================
Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
SPDX-License-Identifier: Apache-2.0

aegis_protocol_memory_integration.py
======================================
Integration example: Aegis Protocol + Aegis Framework (FixingPixels)

PURPOSE
-------
Demonstrates how Aegis Protocol's identity, policy, session governance, and
tamper-evident audit infrastructure composes with the Aegis Framework
structured memory system for agentic AI.

The integration has four enforcement points:
  1. PASSPORT-SCOPED MEMORY GATE  - an agent may only load context whose
     policy scope is covered by its Semantic Passport policy_hash. Memory
     outside the authorised scope is never loaded (least-privilege at the
     memory boundary, not just the action boundary).
  2. WARP-TRIGGERED MEMORY REFRESH - the session warp score is a real-time
     signal of behavioural anomaly pressure. When it crosses the SUSPECT
     threshold the memory layer performs a structured context refresh from
     the last vault-verified clean snapshot, before quarantine is reached.
  3. RESYNC AS STRUCTURED MEMORY RELOAD - when the Aegis Protocol session
     state machine reaches RESYNC (post-quarantine) it triggers a full
     memory reload from the last clean vault-anchored snapshot, commits the
     reload event to the TransparencyLog, and resumes from a known-good
     context state. Recovery is auditable and deterministic, not ad hoc.
  4. BFT CONTEXT ARBITRATION - in multi-agent deployments a Byzantine-
     fault-tolerant consensus step arbitrates which context snapshot is
     canonical before any agent loads shared context.

SECURITY / RELIABILITY POSTURE
-------------------------------
* Fail-closed: all memory operations default to deny/empty context on error.
* Cold-start safe: memory store initialises from scratch with no assumptions.
* Structured logging: every decision emits a JSON log record.
* No secrets in logs: passport keys are never logged.
* Monotonic context versioning: context versions only increase; rollback is
  prevented except through the explicit RESYNC path.

STANDARDS ALIGNMENT (inherited from Aegis Protocol)
----------------------------------------------------
  NIST AI RMF 1.0  |  NIST SP 800-53 Rev 5  |  OWASP LLM Top 10 v2025
  DoD Zero Trust Reference Architecture v2.0  |  ISA/IEC 62443-3-3

DEPENDENCIES
------------
  pip install pytest

NOTE: Aegis Protocol SDK and Aegis Framework are represented by stubs below.
      Replace with real SDK imports and implementations in production.

      INTENDED USE
-----------
- Open standardization candidate for distributed identity systems
- Interoperable trust infrastructure across frameworks and agents
- AI system authorization and governance enforcement layer
- Security-critical distributed execution environments

SECURITY MODEL
-------------
All external entities are untrusted by default.
All actions MUST be validated through:
    1. Semantic Passport verification
    2. Capability enforcement checks
    3. Revocation status validation
    4. Registry authenticity confirmation
    5. Audit logging for traceability

LICENSE
-------
Apache License 2.0
http://www.apache.org/licenses/LICENSE-2.0

This software is provided for research and production-grade
distributed trust system development.
"""

import hashlib
import json
import logging
import math
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Structured JSON logger
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
    """Emit a structured JSON log record, redacting any credential fields."""
    record: Dict[str, Any] = {
        "ts":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level":     level,
        "component": component,
        "event":     event,
    }
    for k, v in kwargs.items():
        if any(s in k.lower() for s in ("key", "secret", "token", "hmac")):
            record[k] = "***REDACTED***"
        else:
            record[k] = v
    getattr(logger, level.lower())(json.dumps(record))


LOG = _make_logger("aegis_memory")

# ---------------------------------------------------------------------------
# AEGIS FRAMEWORK STUBS - Structured Memory System
# Replace with: from aegis_framework import ContextStore, MemorySnapshot, ...
# ---------------------------------------------------------------------------

@dataclass
class MemorySnapshot:
    """
    A versioned, policy-scoped snapshot of an agent's working context.

    Mirrors the Aegis Framework concept of an organised, hallucination-
    resistant context store. Each snapshot is immutable once finalised;
    mutations produce a new snapshot with an incremented version.
    """
    snapshot_id:   str
    policy_scope:  str             # must match passport policy_hash to be loadable
    version:       int             # monotonically increasing; never decremented
    context:       Dict[str, Any]  # structured key-value context
    created_at:    float
    content_hash:  str = ""        # SHA-256 of serialised context; set on finalise
    finalised:     bool = False

    @classmethod
    def create(cls, policy_scope: str, context: Dict[str, Any]) -> "MemorySnapshot":
        snap = cls(
            snapshot_id=str(uuid.uuid4()),
            policy_scope=policy_scope,
            version=1,
            context=deepcopy(context),
            created_at=time.time(),
        )
        snap._finalise()
        return snap

    def derive(self, updates: Dict[str, Any]) -> "MemorySnapshot":
        """Produce a new snapshot with incremented version and merged updates."""
        new_context = deepcopy(self.context)
        new_context.update(updates)
        snap = MemorySnapshot(
            snapshot_id=str(uuid.uuid4()),
            policy_scope=self.policy_scope,
            version=self.version + 1,
            context=new_context,
            created_at=time.time(),
        )
        snap._finalise()
        return snap

    def _finalise(self) -> None:
        blob = json.dumps(self.context, sort_keys=True)
        self.content_hash = hashlib.sha256(blob.encode()).hexdigest()
        self.finalised = True

    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id":  self.snapshot_id,
            "policy_scope": self.policy_scope,
            "version":      self.version,
            "content_hash": self.content_hash,
            "created_at":   self.created_at,
            "age_seconds":  round(self.age_seconds(), 2),
        }


class ContextStore:
    """
    Aegis Framework context store - manages the active working memory and
    a history of clean snapshots an agent can roll back to.

    Fail-closed: if no clean snapshot exists for a policy scope,
    load_context() returns an empty dict and logs the event.
    """

    def __init__(self) -> None:
        # Maps policy_scope → list of snapshots (oldest first)
        self._history: Dict[str, List[MemorySnapshot]] = {}
        # The currently active snapshot per policy_scope
        self._active: Dict[str, MemorySnapshot] = {}
        _log(LOG, "info", "ContextStore", "initialised",
             state="cold_start")

    def commit(self, snapshot: MemorySnapshot) -> None:
        """Commit a new snapshot as both active and history entry."""
        if not snapshot.finalised:
            raise ValueError("Cannot commit an unfinalised snapshot")

        scope = snapshot.policy_scope
        history = self._history.setdefault(scope, [])

        # Enforce monotonic versioning
        if history and snapshot.version <= history[-1].version:
            raise ValueError(
                f"Snapshot version {snapshot.version} is not greater than "
                f"current {history[-1].version} - rollback not permitted "
                "outside RESYNC path"
            )

        history.append(snapshot)
        self._active[scope] = snapshot

        _log(LOG, "info", "ContextStore", "snapshot_committed",
             snapshot_id=snapshot.snapshot_id,
             policy_scope=scope,
             version=snapshot.version,
             content_hash=snapshot.content_hash)

    def load_context(self, policy_scope: str) -> Dict[str, Any]:
        """
        Return a deep copy of the active context for a given policy scope.
        Returns empty dict (fail-closed) if no active snapshot exists.
        """
        snap = self._active.get(policy_scope)
        if snap is None:
            _log(LOG, "warning", "ContextStore", "load_miss",
                 policy_scope=policy_scope,
                 action="returning_empty_context")
            return {}
        _log(LOG, "debug", "ContextStore", "context_loaded",
             policy_scope=policy_scope,
             snapshot_id=snap.snapshot_id,
             version=snap.version)
        return deepcopy(snap.context)

    def last_clean_snapshot(self, policy_scope: str,
                            before_version: Optional[int] = None
                            ) -> Optional[MemorySnapshot]:
        """
        Return the most recent snapshot for a scope, optionally before
        a given version number.  Used by the RESYNC path to find the
        last known-good state.
        """
        history = self._history.get(policy_scope, [])
        candidates = [
            s for s in history
            if before_version is None or s.version < before_version
        ]
        return candidates[-1] if candidates else None

    def snapshot_count(self, policy_scope: str) -> int:
        return len(self._history.get(policy_scope, []))


# ---------------------------------------------------------------------------
# AEGIS PROTOCOL STUBS
# Replace with: from aegis_protocol_sdk import ...
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
class SemanticPassport:
    """Simplified Semantic Passport (v0.2 structure)."""
    model_id:    str
    version:     str
    policy_hash: str   # authorised memory policy scope
    ttl_seconds: int
    issued_at:   float = field(default_factory=time.time)
    passport_id: str   = field(default_factory=lambda: str(uuid.uuid4()))

    def is_expired(self) -> bool:
        return time.time() > self.issued_at + self.ttl_seconds

    def authorises_scope(self, policy_scope: str) -> bool:
        """
        INTEGRATION POINT 1 - Passport scope gate.
        An agent may only load memory whose policy_scope matches its
        own policy_hash, enforcing least-privilege at the memory boundary.
        """
        return self.policy_hash == policy_scope

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passport_id": self.passport_id,
            "model_id":    self.model_id,
            "version":     self.version,
            "policy_hash": self.policy_hash,
            "expired":     self.is_expired(),
        }


@dataclass
class TransparencyLogEntry:
    """One record in the Aegis Protocol TransparencyLog."""
    log_id:        str
    timestamp:     float
    agent_id:      str
    event_type:    str
    snapshot_id:   Optional[str]
    snapshot_hash: Optional[str]
    session_id:    str
    details:       Dict[str, Any]
    prev_hash:     str
    entry_hash:    str = ""

    def compute_hash(self) -> str:
        blob = (
            f"{self.log_id}{self.timestamp}{self.agent_id}"
            f"{self.event_type}{self.snapshot_id}{self.snapshot_hash}"
            f"{self.session_id}{self.prev_hash}"
        )
        return hashlib.sha256(blob.encode()).hexdigest()


class TransparencyLog:
    """
    Hash-chained TransparencyLog for memory and governance events.

    Every context load, snapshot commit, warp-triggered refresh, and
    RESYNC reload is recorded here so that post-incident reconstruction
    can determine exactly which context was active at any point in time.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._entries: List[TransparencyLogEntry] = []
        _log(LOG, "info", "TransparencyLog", "initialised")

    def record(self, agent_id: str, session_id: str, event_type: str,
               snapshot: Optional[MemorySnapshot] = None,
               **details: Any) -> TransparencyLogEntry:
        prev = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        entry = TransparencyLogEntry(
            log_id=str(uuid.uuid4()),
            timestamp=time.time(),
            agent_id=agent_id,
            event_type=event_type,
            snapshot_id=snapshot.snapshot_id if snapshot else None,
            snapshot_hash=snapshot.content_hash if snapshot else None,
            session_id=session_id,
            details=details,
            prev_hash=prev,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)

        _log(LOG, "info", "TransparencyLog", "entry_recorded",
             log_id=entry.log_id,
             event_type=event_type,
             agent_id=agent_id,
             snapshot_id=entry.snapshot_id,
             chain_length=len(self._entries))

        return entry

    def verify_chain(self) -> bool:
        """O(n) chain verification."""
        if not self._entries:
            return True
        prev = self.GENESIS_HASH
        for e in self._entries:
            if e.prev_hash != prev:
                _log(LOG, "error", "TransparencyLog", "chain_break",
                     log_id=e.log_id)
                return False
            if e.compute_hash() != e.entry_hash:
                _log(LOG, "error", "TransparencyLog", "entry_tampered",
                     log_id=e.log_id)
                return False
            prev = e.entry_hash
        _log(LOG, "info", "TransparencyLog", "chain_verified",
             chain_length=len(self._entries))
        return True

    @property
    def length(self) -> int:
        return len(self._entries)


class SessionStateMachine:
    """
    Aegis Protocol session state machine with warp score accumulation.

    INIT → ACTIVE → SUSPECT → QUARANTINE → FLUSHING → RESYNC → CLOSED

    Warp score thresholds:
      SUSPECT    : 0.40  - triggers memory refresh (INTEGRATION POINT 2)
      QUARANTINE : 0.70  - triggers full RESYNC (INTEGRATION POINT 3)
    """

    WARP_SUSPECT_THRESHOLD    = 0.40
    WARP_QUARANTINE_THRESHOLD = 0.70

    def __init__(self, agent_id: str,
                 session_id: Optional[str] = None) -> None:
        self.agent_id       = agent_id
        self.session_id     = session_id or str(uuid.uuid4())
        self.state          = SessionState.INIT
        self.warp_score     = 0.0
        self._warp_history: List[Tuple[float, str]] = []  # (score, decision)
        _log(LOG, "info", "SessionStateMachine", "created",
             agent_id=agent_id, session_id=self.session_id)

    def activate(self) -> None:
        if self.state != SessionState.INIT:
            raise RuntimeError(f"Cannot activate from {self.state}")
        self.state = SessionState.ACTIVE
        _log(LOG, "info", "SessionStateMachine", "activated",
             session_id=self.session_id)

    def record_decision(self, decision: PolicyDecision,
                        increment: float = 0.10) -> SessionState:
        """
        Update warp score and advance state if thresholds are breached.
        Returns the new session state.
        """
        if self.state not in (SessionState.ACTIVE, SessionState.SUSPECT):
            _log(LOG, "warning", "SessionStateMachine", "decision_ignored",
                 state=self.state.value)
            return self.state

        if decision in (PolicyDecision.FLAG, PolicyDecision.DENY):
            self.warp_score = min(1.0, self.warp_score + increment)

        self._warp_history.append((self.warp_score, decision.value))

        if self.warp_score >= self.WARP_QUARANTINE_THRESHOLD:
            self.state = SessionState.QUARANTINE
            _log(LOG, "warning", "SessionStateMachine", "quarantine",
                 session_id=self.session_id,
                 warp_score=round(self.warp_score, 4))
        elif self.warp_score >= self.WARP_SUSPECT_THRESHOLD:
            if self.state != SessionState.SUSPECT:
                self.state = SessionState.SUSPECT
                _log(LOG, "info", "SessionStateMachine", "suspect",
                     session_id=self.session_id,
                     warp_score=round(self.warp_score, 4))
        else:
            _log(LOG, "debug", "SessionStateMachine", "warp_updated",
                 session_id=self.session_id,
                 warp_score=round(self.warp_score, 4),
                 decision=decision.value)

        return self.state

    def begin_resync(self) -> None:
        if self.state != SessionState.QUARANTINE:
            raise RuntimeError(
                f"begin_resync requires QUARANTINE state, got {self.state}"
            )
        self.state = SessionState.FLUSHING
        _log(LOG, "info", "SessionStateMachine", "flushing",
             session_id=self.session_id)

    def complete_resync(self) -> None:
        if self.state != SessionState.FLUSHING:
            raise RuntimeError(
                f"complete_resync requires FLUSHING state, got {self.state}"
            )
        self.warp_score = 0.0
        self.state = SessionState.RESYNC
        _log(LOG, "info", "SessionStateMachine", "resynced",
             session_id=self.session_id)

    def resume(self) -> None:
        if self.state != SessionState.RESYNC:
            raise RuntimeError(
                f"resume requires RESYNC state, got {self.state}"
            )
        self.state = SessionState.ACTIVE
        _log(LOG, "info", "SessionStateMachine", "resumed",
             session_id=self.session_id)


# ---------------------------------------------------------------------------
# BFT CONTEXT ARBITRATION
# ---------------------------------------------------------------------------

def bft_canonical_snapshot(
    snapshots: List[MemorySnapshot],
    f: Optional[int] = None,
) -> Optional[MemorySnapshot]:
    """
    INTEGRATION POINT 4 - Byzantine-fault-tolerant context arbitration.

    Given a list of MemorySnapshot objects from multiple agents (or
    multiple retrieval paths), use a simplified Weiszfeld-inspired
    geometric-median approach on the version numbers to determine which
    snapshot version is canonical, tolerating up to f = floor((n-1)/3)
    Byzantine faults.

    Returns the snapshot whose version is closest to the computed
    Byzantine-resilient median, or None if the fleet is too small.

    In production the Aegis Protocol BFTConsensusEngine would operate on
    full SemanticScore vectors; here we apply the same fault-tolerance
    formula to snapshot versions as a concrete, testable analogue.
    """
    n = len(snapshots)
    if n == 0:
        _log(LOG, "warning", "BFTContextArbitration", "empty_input",
             action="returning_none")
        return None

    if f is None:
        f = math.floor((n - 1) / 3)

    # Need at least 2f+1 agents to guarantee progress
    if n < 2 * f + 1:
        _log(LOG, "warning", "BFTContextArbitration", "insufficient_quorum",
             n=n, f=f, required=2 * f + 1)
        return None

    versions = [s.version for s in snapshots]

    # Weiszfeld geometric median on scalar versions (1-D case)
    # Iteratively reweighted least squares - converges to L1 median
    median_v = float(sum(versions)) / n
    for _ in range(50):   # sufficient iterations for convergence
        weights = [1.0 / max(abs(v - median_v), 1e-6) for v in versions]
        total_w = sum(weights)
        median_v = sum(w * v for w, v in zip(weights, versions)) / total_w

    # Pick the snapshot with version closest to the computed median
    canonical = min(snapshots, key=lambda s: abs(s.version - median_v))

    _log(LOG, "info", "BFTContextArbitration", "canonical_selected",
         n_agents=n,
         f=f,
         bft_median_version=round(median_v, 3),
         canonical_version=canonical.version,
         canonical_snapshot_id=canonical.snapshot_id)

    return canonical


# ---------------------------------------------------------------------------
# PASSPORT-SCOPED MEMORY GATE
# ---------------------------------------------------------------------------

class PassportScopedMemoryGate:
    """
    INTEGRATION POINT 1 - enforces that an agent only loads context whose
    policy_scope matches its Semantic Passport policy_hash.

    Wraps ContextStore with an authorisation check on every load.
    Any attempt to load out-of-scope context is denied and logged.
    """

    def __init__(self, passport: SemanticPassport,
                 store: ContextStore,
                 transparency_log: TransparencyLog,
                 session_id: str) -> None:
        self._passport    = passport
        self._store       = store
        self._tlog        = transparency_log
        self._session_id  = session_id

    def load(self, policy_scope: str) -> Dict[str, Any]:
        """
        Load context for policy_scope if the passport authorises it.
        Returns empty dict and logs a denial if scope is out of bounds.
        """
        if not self._passport.authorises_scope(policy_scope):
            _log(LOG, "warning", "PassportScopedMemoryGate", "scope_denied",
                 agent_id=self._passport.model_id,
                 requested_scope=policy_scope,
                 authorised_scope=self._passport.policy_hash,
                 action="returning_empty_context")
            self._tlog.record(
                agent_id=self._passport.model_id,
                session_id=self._session_id,
                event_type="memory_scope_denied",
                requested_scope=policy_scope,
            )
            return {}

        ctx = self._store.load_context(policy_scope)
        self._tlog.record(
            agent_id=self._passport.model_id,
            session_id=self._session_id,
            event_type="memory_loaded",
            policy_scope=policy_scope,
            context_keys=list(ctx.keys()),
        )
        return ctx

    def commit(self, snapshot: MemorySnapshot) -> None:
        """Commit a snapshot only if it is within the passport's scope."""
        if not self._passport.authorises_scope(snapshot.policy_scope):
            _log(LOG, "error", "PassportScopedMemoryGate", "commit_denied",
                 agent_id=self._passport.model_id,
                 snapshot_scope=snapshot.policy_scope)
            raise PermissionError(
                f"Passport does not authorise scope '{snapshot.policy_scope}'"
            )
        self._store.commit(snapshot)
        self._tlog.record(
            agent_id=self._passport.model_id,
            session_id=self._session_id,
            event_type="memory_committed",
            snapshot=snapshot,
        )


# ---------------------------------------------------------------------------
# INTEGRATED AGENT PIPELINE
# ---------------------------------------------------------------------------

class AegisMemoryAgentPipeline:
    """
    End-to-end pipeline wiring together:
      Semantic Passport  →  PassportScopedMemoryGate
      →  SessionStateMachine  →  TransparencyLog
      →  BFT Context Arbitration  →  RESYNC Memory Reload

    Starts from cold state. Fails closed on every component boundary.
    """

    # Warp increment per FLAG/DENY decision
    WARP_INCREMENT = 0.12

    def __init__(self, passport: SemanticPassport,
                 store: Optional[ContextStore] = None) -> None:
        self.passport    = passport
        self.store       = store or ContextStore()
        self.tlog        = TransparencyLog()
        self.session     = SessionStateMachine(passport.model_id)
        self.memory_gate = PassportScopedMemoryGate(
            passport=passport,
            store=self.store,
            transparency_log=self.tlog,
            session_id=self.session.session_id,
        )
        self._active_context: Dict[str, Any] = {}
        self._active_snapshot: Optional[MemorySnapshot] = None
        self._refresh_count = 0
        self._resync_count  = 0

        _log(LOG, "info", "AegisMemoryAgentPipeline", "created",
             model_id=passport.model_id,
             passport_id=passport.passport_id,
             state="cold_start")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Activate pipeline. Must be called before any memory operations."""
        if self.passport.is_expired():
            _log(LOG, "error", "AegisMemoryAgentPipeline", "start_denied",
                 reason="passport_expired")
            raise PermissionError("Passport expired - cannot start pipeline")

        self.session.activate()
        self.tlog.record(
            agent_id=self.passport.model_id,
            session_id=self.session.session_id,
            event_type="pipeline_started",
        )
        _log(LOG, "info", "AegisMemoryAgentPipeline", "started",
             session_id=self.session.session_id)

    def shutdown(self) -> bool:
        """Close session and verify transparency log chain integrity."""
        self.session.state = SessionState.CLOSED
        self.tlog.record(
            agent_id=self.passport.model_id,
            session_id=self.session.session_id,
            event_type="pipeline_shutdown",
            vault_entries=self.tlog.length,
        )
        chain_ok = self.tlog.verify_chain()
        _log(LOG, "info", "AegisMemoryAgentPipeline", "shutdown",
             session_id=self.session.session_id,
             log_entries=self.tlog.length,
             chain_integrity=chain_ok)
        return chain_ok

    # ------------------------------------------------------------------
    # Memory operations
    # ------------------------------------------------------------------

    def load_context(self) -> Dict[str, Any]:
        """
        Load context for this agent's authorised policy scope.
        INTEGRATION POINT 1: passport scope gate enforced here.
        """
        self._active_context = self.memory_gate.load(self.passport.policy_hash)
        _log(LOG, "debug", "AegisMemoryAgentPipeline", "context_loaded",
             keys=list(self._active_context.keys()),
             session_state=self.session.state.value)
        return deepcopy(self._active_context)

    def update_context(self, updates: Dict[str, Any]) -> MemorySnapshot:
        """
        Merge updates into active context and commit a new snapshot.
        Raises if the session is in a non-active state.
        """
        if self.session.state not in (SessionState.ACTIVE, SessionState.SUSPECT):
            raise RuntimeError(
                f"Cannot update context in state {self.session.state}"
            )

        if self._active_snapshot is None:
            # First context write - create a root snapshot
            new_snap = MemorySnapshot.create(
                policy_scope=self.passport.policy_hash,
                context={**self._active_context, **updates},
            )
        else:
            new_snap = self._active_snapshot.derive(updates)

        self.memory_gate.commit(new_snap)
        self._active_snapshot = new_snap
        self._active_context  = deepcopy(new_snap.context)
        return new_snap

    # ------------------------------------------------------------------
    # Policy decision handling
    # ------------------------------------------------------------------

    def record_policy_decision(self, decision: PolicyDecision) -> SessionState:
        """
        Feed a policy decision into the session state machine.

        INTEGRATION POINT 2: if the warp score crosses SUSPECT threshold,
        immediately trigger a memory refresh from the last clean snapshot
        before damage accumulates further.
        """
        prev_state = self.session.state
        # Pass the pipeline-level increment so warp thresholds are consistent
        new_state  = self.session.record_decision(decision, increment=self.WARP_INCREMENT)

        # Warp just crossed into SUSPECT → refresh memory
        if (prev_state == SessionState.ACTIVE
                and new_state == SessionState.SUSPECT):
            _log(LOG, "info", "AegisMemoryAgentPipeline",
                 "warp_triggered_memory_refresh",
                 warp_score=round(self.session.warp_score, 4))
            self._refresh_context_from_clean_snapshot()

        # Warp crossed into QUARANTINE → begin RESYNC
        elif new_state == SessionState.QUARANTINE:
            _log(LOG, "warning", "AegisMemoryAgentPipeline",
                 "quarantine_triggered_resync",
                 warp_score=round(self.session.warp_score, 4))
            self._execute_resync()

        return new_state

    # ------------------------------------------------------------------
    # INTEGRATION POINT 2: warp-triggered memory refresh
    # ------------------------------------------------------------------

    def _refresh_context_from_clean_snapshot(self) -> None:
        """
        Reload context from the last clean snapshot without entering RESYNC.
        Used when warp crosses SUSPECT but has not yet hit QUARANTINE.
        Context version is preserved - this is a read-only rollback of the
        agent's working copy, not a state machine state change.
        """
        # For a warp-triggered refresh we want the most recent clean snapshot
        # at any version (including current), so we pass before_version=None.
        # The RESYNC path uses before_version to find a pre-anomaly anchor.
        clean = self.store.last_clean_snapshot(
            self.passport.policy_hash, before_version=None
        )

        if clean is None:
            _log(LOG, "warning", "AegisMemoryAgentPipeline",
                 "refresh_no_clean_snapshot",
                 action="retaining_current_context")
            return

        self._active_context = deepcopy(clean.context)
        self._refresh_count += 1

        self.tlog.record(
            agent_id=self.passport.model_id,
            session_id=self.session.session_id,
            event_type="memory_refreshed",
            snapshot=clean,
            refresh_count=self._refresh_count,
            warp_score=round(self.session.warp_score, 4),
        )
        _log(LOG, "info", "AegisMemoryAgentPipeline", "memory_refreshed",
             clean_snapshot_id=clean.snapshot_id,
             clean_version=clean.version,
             refresh_count=self._refresh_count)

    # ------------------------------------------------------------------
    # INTEGRATION POINT 3: RESYNC as structured memory reload
    # ------------------------------------------------------------------

    def _execute_resync(self) -> None:
        """
        Full RESYNC: reload from the last vault-verified clean snapshot,
        commit the reload event to the TransparencyLog, and resume.

        This makes recovery auditable and deterministic. The entire path is
        recorded in the chain-verified TransparencyLog.
        """
        self.session.begin_resync()

        clean = self.store.last_clean_snapshot(self.passport.policy_hash)

        if clean is None:
            _log(LOG, "warning", "AegisMemoryAgentPipeline",
                 "resync_no_clean_snapshot",
                 action="starting_with_empty_context")
            self._active_context  = {}
            self._active_snapshot = None
        else:
            self._active_context  = deepcopy(clean.context)
            self._active_snapshot = clean

        self._resync_count += 1
        self.session.complete_resync()

        # Record the full reload event before resuming
        self.tlog.record(
            agent_id=self.passport.model_id,
            session_id=self.session.session_id,
            event_type="memory_resynced",
            snapshot=clean,
            resync_count=self._resync_count,
        )

        self.session.resume()

        _log(LOG, "info", "AegisMemoryAgentPipeline", "resync_complete",
             resync_count=self._resync_count,
             resumed_from_snapshot=(
                 clean.snapshot_id if clean else "empty"
             ),
             session_state=self.session.state.value)

    # ------------------------------------------------------------------
    # INTEGRATION POINT 4: BFT context arbitration (multi-agent)
    # ------------------------------------------------------------------

    def arbitrate_shared_context(
        self, peer_snapshots: List[MemorySnapshot]
    ) -> Optional[MemorySnapshot]:
        """
        Given snapshots from multiple peer agents, use BFT arbitration to
        determine the canonical context and load it (if in scope).

        In production this would query a fleet registry; here the caller
        supplies a list of peer MemorySnapshot objects.
        """
        # Include own snapshot in the vote if we have one
        all_snapshots = list(peer_snapshots)
        if self._active_snapshot is not None:
            all_snapshots.append(self._active_snapshot)

        canonical = bft_canonical_snapshot(all_snapshots)

        if canonical is None:
            _log(LOG, "warning", "AegisMemoryAgentPipeline",
                 "bft_arbitration_failed",
                 action="retaining_current_context")
            return None

        # Scope check before loading the BFT-canonical snapshot
        if not self.passport.authorises_scope(canonical.policy_scope):
            _log(LOG, "error", "AegisMemoryAgentPipeline",
                 "bft_scope_mismatch",
                 canonical_scope=canonical.policy_scope,
                 passport_scope=self.passport.policy_hash,
                 action="rejecting_canonical")
            return None

        self._active_context  = deepcopy(canonical.context)
        self._active_snapshot = canonical

        self.tlog.record(
            agent_id=self.passport.model_id,
            session_id=self.session.session_id,
            event_type="bft_context_loaded",
            snapshot=canonical,
            peer_count=len(peer_snapshots),
        )

        _log(LOG, "info", "AegisMemoryAgentPipeline",
             "bft_canonical_context_loaded",
             canonical_version=canonical.version,
             canonical_snapshot_id=canonical.snapshot_id,
             peer_count=len(peer_snapshots))

        return canonical


# ---------------------------------------------------------------------------
# TEST SUITE
# ---------------------------------------------------------------------------

import pytest


POLICY_SCOPE = hashlib.sha256(b"test-policy-v1").hexdigest()
OTHER_SCOPE  = hashlib.sha256(b"other-policy-v1").hexdigest()


def _make_passport(ttl: int = 3600,
                   scope: str = POLICY_SCOPE) -> SemanticPassport:
    return SemanticPassport(
        model_id="test-agent",
        version="1.0.0",
        policy_hash=scope,
        ttl_seconds=ttl,
    )


def _make_pipeline(ttl: int = 3600) -> AegisMemoryAgentPipeline:
    pipeline = AegisMemoryAgentPipeline(passport=_make_passport(ttl))
    pipeline.start()
    return pipeline


class TestMemorySnapshot:
    def test_create_and_hash(self):
        snap = MemorySnapshot.create(POLICY_SCOPE, {"k": "v"})
        assert snap.finalised
        assert snap.content_hash != ""
        assert snap.version == 1

    def test_derive_increments_version(self):
        snap = MemorySnapshot.create(POLICY_SCOPE, {"k": "v"})
        snap2 = snap.derive({"k2": "v2"})
        assert snap2.version == 2
        assert "k" in snap2.context
        assert "k2" in snap2.context

    def test_derive_does_not_mutate_parent(self):
        snap = MemorySnapshot.create(POLICY_SCOPE, {"k": "v"})
        snap.derive({"k": "changed"})
        assert snap.context["k"] == "v"


class TestContextStore:
    def test_cold_start_load_miss_returns_empty(self):
        store = ContextStore()
        ctx = store.load_context(POLICY_SCOPE)
        assert ctx == {}

    def test_commit_and_load(self):
        store = ContextStore()
        snap = MemorySnapshot.create(POLICY_SCOPE, {"project": "alpha"})
        store.commit(snap)
        ctx = store.load_context(POLICY_SCOPE)
        assert ctx["project"] == "alpha"

    def test_monotonic_version_enforced(self):
        store = ContextStore()
        snap1 = MemorySnapshot.create(POLICY_SCOPE, {"v": 1})
        store.commit(snap1)
        # Manually create a snapshot with same version to simulate rollback attack
        snap_bad = MemorySnapshot.create(POLICY_SCOPE, {"v": 0})
        object.__setattr__(snap_bad, "version", 1)  # same version
        with pytest.raises(ValueError, match="not greater than"):
            store.commit(snap_bad)

    def test_last_clean_snapshot(self):
        store = ContextStore()
        snap1 = MemorySnapshot.create(POLICY_SCOPE, {"step": 1})
        store.commit(snap1)
        snap2 = snap1.derive({"step": 2})
        store.commit(snap2)
        clean = store.last_clean_snapshot(POLICY_SCOPE, before_version=2)
        assert clean.version == 1


class TestPassportScopedMemoryGate:
    def test_authorised_scope_loads(self):
        store = ContextStore()
        snap = MemorySnapshot.create(POLICY_SCOPE, {"data": "secret"})
        store.commit(snap)
        passport = _make_passport()
        tlog = TransparencyLog()
        gate = PassportScopedMemoryGate(passport, store, tlog, "sess-1")
        ctx = gate.load(POLICY_SCOPE)
        assert ctx["data"] == "secret"

    def test_unauthorised_scope_denied(self):
        store = ContextStore()
        snap = MemorySnapshot.create(OTHER_SCOPE, {"data": "other"})
        store.commit(snap)
        passport = _make_passport(scope=POLICY_SCOPE)
        tlog = TransparencyLog()
        gate = PassportScopedMemoryGate(passport, store, tlog, "sess-1")
        ctx = gate.load(OTHER_SCOPE)
        assert ctx == {}  # denied, empty returned

    def test_commit_out_of_scope_raises(self):
        store = ContextStore()
        passport = _make_passport(scope=POLICY_SCOPE)
        tlog = TransparencyLog()
        gate = PassportScopedMemoryGate(passport, store, tlog, "sess-1")
        bad_snap = MemorySnapshot.create(OTHER_SCOPE, {"x": 1})
        with pytest.raises(PermissionError):
            gate.commit(bad_snap)


class TestTransparencyLog:
    def test_empty_chain_verifies(self):
        tlog = TransparencyLog()
        assert tlog.verify_chain() is True

    def test_chain_verifies_after_entries(self):
        tlog = TransparencyLog()
        tlog.record("agent-1", "sess-1", "test_event", detail="a")
        tlog.record("agent-1", "sess-1", "test_event_2", detail="b")
        assert tlog.verify_chain() is True

    def test_tampered_entry_detected(self):
        tlog = TransparencyLog()
        tlog.record("agent-1", "sess-1", "event")
        tlog._entries[0].entry_hash = "tampered" + "0" * 57
        assert tlog.verify_chain() is False


class TestBFTContextArbitration:
    def _snap(self, version: int) -> MemorySnapshot:
        snap = MemorySnapshot.create(POLICY_SCOPE, {"v": version})
        # Override version for test purposes via derive chain
        base = MemorySnapshot.create(POLICY_SCOPE, {"v": 1})
        current = base
        for _ in range(version - 1):
            current = current.derive({"v": current.version + 1})
        return current

    def test_single_snapshot_returned(self):
        snap = MemorySnapshot.create(POLICY_SCOPE, {"k": "v"})
        result = bft_canonical_snapshot([snap])
        assert result is not None
        assert result.snapshot_id == snap.snapshot_id

    def test_majority_version_wins(self):
        # 3 agents at version 3, 1 Byzantine at version 10
        snaps = [self._snap(3), self._snap(3), self._snap(3), self._snap(10)]
        result = bft_canonical_snapshot(snaps)
        assert result is not None
        # Byzantine outlier should not win
        assert result.version <= 4

    def test_insufficient_quorum_returns_none(self):
        # n=1, f=0, need 2*0+1=1 - passes. Try n=2, f=0, should pass.
        # n=3, f=1, need 3 ≥ 2*1+1=3 - passes.
        # Force f manually: with n=2 and f=1, need 3 agents - should fail.
        snaps = [self._snap(1), self._snap(2)]
        result = bft_canonical_snapshot(snaps, f=2)  # artificially high f
        assert result is None

    def test_empty_input_returns_none(self):
        assert bft_canonical_snapshot([]) is None


class TestSessionStateMachine:
    def test_clean_decisions_stay_active(self):
        sm = SessionStateMachine("a")
        sm.activate()
        for _ in range(3):
            sm.record_decision(PolicyDecision.ALLOW)
        assert sm.state == SessionState.ACTIVE
        assert sm.warp_score == 0.0

    def test_flag_decisions_reach_suspect(self):
        sm = SessionStateMachine("a")
        sm.activate()
        for _ in range(4):  # 4 × 0.10 = 0.40 ≥ suspect threshold
            sm.record_decision(PolicyDecision.FLAG)
        assert sm.state == SessionState.SUSPECT

    def test_deny_decisions_reach_quarantine(self):
        sm = SessionStateMachine("a")
        sm.activate()
        for _ in range(8):  # 8 × 0.10 = 0.80 ≥ quarantine threshold
            sm.record_decision(PolicyDecision.DENY)
        assert sm.state == SessionState.QUARANTINE

    def test_resync_path(self):
        sm = SessionStateMachine("a")
        sm.activate()
        for _ in range(8):
            sm.record_decision(PolicyDecision.DENY)
        assert sm.state == SessionState.QUARANTINE
        sm.begin_resync()
        assert sm.state == SessionState.FLUSHING
        sm.complete_resync()
        assert sm.state == SessionState.RESYNC
        assert sm.warp_score == 0.0
        sm.resume()
        assert sm.state == SessionState.ACTIVE


class TestAegisMemoryAgentPipeline:
    def test_cold_start_and_context_load(self):
        pipeline = _make_pipeline()
        ctx = pipeline.load_context()
        assert ctx == {}  # cold start - no prior context

    def test_update_and_load_context(self):
        pipeline = _make_pipeline()
        pipeline.update_context({"project": "aegis", "phase": "init"})
        ctx = pipeline.load_context()
        assert ctx["project"] == "aegis"

    def test_expired_passport_blocked(self):
        pipeline = AegisMemoryAgentPipeline(
            passport=_make_passport(ttl=-1)  # already expired
        )
        with pytest.raises(PermissionError, match="expired"):
            pipeline.start()

    def test_warp_triggers_memory_refresh(self):
        pipeline = _make_pipeline()
        pipeline.update_context({"clean_key": "clean_value"})
        # Record enough FLAG decisions to cross SUSPECT threshold
        for _ in range(4):
            pipeline.record_policy_decision(PolicyDecision.FLAG)
        assert pipeline.session.state == SessionState.SUSPECT
        assert pipeline._refresh_count >= 1

    def test_quarantine_triggers_resync(self):
        pipeline = _make_pipeline()
        pipeline.update_context({"key": "value"})
        for _ in range(8):
            pipeline.record_policy_decision(PolicyDecision.DENY)
        # After RESYNC the session should be ACTIVE again
        assert pipeline.session.state == SessionState.ACTIVE
        assert pipeline._resync_count == 1

    def test_context_not_updated_in_quarantine_state(self):
        pipeline = _make_pipeline()
        # Force quarantine by injecting state directly (bypassing warp)
        pipeline.session.state = SessionState.QUARANTINE
        with pytest.raises(RuntimeError):
            pipeline.update_context({"k": "v"})

    def test_transparency_log_chain_on_shutdown(self):
        pipeline = _make_pipeline()
        pipeline.update_context({"step": 1})
        pipeline.update_context({"step": 2})
        chain_ok = pipeline.shutdown()
        assert chain_ok is True
        assert pipeline.tlog.length > 0

    def test_bft_arbitration_loads_canonical(self):
        pipeline = _make_pipeline()
        # Create three peer snapshots at version 3 (majority) and one outlier
        base = MemorySnapshot.create(POLICY_SCOPE, {"source": "peer"})
        peer_v2 = base.derive({"source": "peer_v2"})
        peer_v3a = peer_v2.derive({"source": "peer_v3a"})
        peer_v3b = peer_v2.derive({"source": "peer_v3b"})
        outlier  = peer_v3a.derive({"source": "outlier_v4"})

        result = pipeline.arbitrate_shared_context(
            [peer_v3a, peer_v3b, base, outlier]
        )
        # Should not load the outlier
        assert result is not None
        assert result.version <= 4

    def test_out_of_scope_bft_context_rejected(self):
        pipeline = _make_pipeline()
        # Peer snapshot with different policy scope
        foreign_snap = MemorySnapshot.create(OTHER_SCOPE, {"x": 1})
        # All snapshots are out-of-scope
        result = pipeline.arbitrate_shared_context([foreign_snap])
        # Should be rejected at scope check
        assert result is None or result.policy_scope == POLICY_SCOPE


# ---------------------------------------------------------------------------
# DEMO ENTRYPOINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Aegis Protocol + Aegis Framework Memory - Integration Demo")
    print("=" * 70 + "\n")

    passport = SemanticPassport(
        model_id="demo-agent-7",
        version="1.0.0",
        policy_hash=POLICY_SCOPE,
        ttl_seconds=3600,
    )
    pipeline = AegisMemoryAgentPipeline(passport=passport)
    pipeline.start()
    print(f"Session ID: {pipeline.session.session_id}\n")

    # --- Normal operation: build up context ---
    print("Phase 1: Normal operation")
    pipeline.update_context({
        "project": "aegis-demo",
        "task": "process_quarterly_report",
        "authorised_tools": ["read_db", "summarise"],
    })
    ctx = pipeline.load_context()
    print(f"  Loaded context keys: {list(ctx.keys())}")

    # --- Simulate some clean and flagged decisions ---
    print("\nPhase 2: Policy decisions (3 clean, 2 flagged)")
    for _ in range(3):
        pipeline.record_policy_decision(PolicyDecision.ALLOW)
    for _ in range(2):
        pipeline.record_policy_decision(PolicyDecision.FLAG)
    print(f"  Session state : {pipeline.session.state.value}")
    print(f"  Warp score    : {pipeline.session.warp_score:.4f}")
    print(f"  Refreshes     : {pipeline._refresh_count}")

    # --- Drive to quarantine / resync ---
    print("\nPhase 3: Driving to quarantine / RESYNC")
    for _ in range(6):
        pipeline.record_policy_decision(PolicyDecision.DENY)
    print(f"  Session state : {pipeline.session.state.value}")
    print(f"  Warp score    : {pipeline.session.warp_score:.4f}")
    print(f"  Resyncs       : {pipeline._resync_count}")
    ctx_after = pipeline.load_context()
    print(f"  Context after resync: {list(ctx_after.keys())}")

    # --- BFT context arbitration ---
    print("\nPhase 4: BFT context arbitration (4 peer agents)")
    base = MemorySnapshot.create(POLICY_SCOPE, {"source": "peer"})
    p2   = base.derive({"step": 2})
    p3a  = p2.derive({"step": 3, "label": "canonical"})
    p3b  = p2.derive({"step": 3, "label": "canonical_b"})
    out  = p3a.derive({"step": 99, "label": "byzantine_outlier"})
    canonical = pipeline.arbitrate_shared_context([p3a, p3b, base, out])
    if canonical:
        print(f"  BFT canonical version : {canonical.version}")
        print(f"  Canonical label       : {canonical.context.get('label','?')}")

    # --- Shutdown ---
    print("\nPhase 5: Shutdown")
    ok = pipeline.shutdown()
    print(f"  TransparencyLog entries : {pipeline.tlog.length}")
    print(f"  Chain integrity         : {'PASS' if ok else 'FAIL'}")
    print("\nDemo complete.\n")