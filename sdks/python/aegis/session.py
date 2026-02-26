"""
aegis.session
~~~~~~~~~~~~~
Session state machine with automatic Entropy Flush on contamination detection.

The Session is the core contamination detection and response mechanism.
It tracks Warp Score across all policy decisions for a given peer and
automatically quarantines and flushes when the threshold is exceeded.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, List, Optional

from .crypto import sha256_hex
from .policy import PolicyAction, PolicyDecision
from .exceptions import SessionStateError, SessionTaintError, SessionQuarantineError


class SessionState(Enum):
    """All valid states in the UML-001 session state machine."""

    INIT       = "INIT"       # handshake in progress
    ACTIVE     = "ACTIVE"     # normal operation
    SUSPECT    = "SUSPECT"    # first DENY detected; monitoring closely
    QUARANTINE = "QUARANTINE" # warp threshold exceeded; flush triggered
    FLUSHING   = "FLUSHING"   # entropy flush in progress
    RESYNC     = "RESYNC"     # flush complete; awaiting clean re-handshake
    CLOSED     = "CLOSED"     # session terminated


# Warp Score accumulation constants
_WARP_ON_DENY  =  1.0
_WARP_ON_FLAG  =  0.5
_WARP_ON_ALLOW = -0.1   # decay; floor 0.0


@dataclass
class SessionEvent:
    """A single entry in the session event log."""
    timestamp:    int
    event_type:   str   # "PAYLOAD" | "DECISION" | "STATE_CHANGE" | "FLUSH"
    payload_hash: str
    detail:       str


# Flush callback type: (session_id, incident_id, tainted_payload_hashes) -> None
FlushCallback = Callable[[str, str, List[str]], None]


class Session:
    """Tracks state for one peer connection.

    Manages the full lifecycle from INIT through CLOSED, including automatic
    quarantine and Entropy Flush when the Warp Score exceeds the threshold.

    Args:
        session_id:      SHA-256 session identifier from the handshake.
        peer_model_id:   model_id of the remote peer.
        warp_threshold:  Warp Score at which QUARANTINE is triggered. Default 3.0.
        on_flush:        Optional callback invoked on Entropy Flush. Receives
                         (session_id, incident_id, tainted_payload_hashes).
        max_buffer:      Maximum number of payload hashes to retain in the
                         taint buffer. Default 256.

    Example::

        def on_flush(session_id, incident_id, tainted):
            vault.append("FLUSH", session_id, peer_id,
                         "", f"incident={incident_id}", now)

        session = Session(session_id, "agent-beta", on_flush=on_flush)
        session.activate()

        score    = classifier.score(payload)
        decision = engine.evaluate(score)

        if not session.process_decision(decision, now=int(time.time())):
            # payload denied or session quarantined
            raise SessionQuarantineError()
    """

    MAX_BUFFER = 256

    def __init__(
        self,
        session_id: str,
        peer_model_id: str,
        warp_threshold: float = 3.0,
        on_flush: Optional[FlushCallback] = None,
        max_buffer: int = MAX_BUFFER,
    ) -> None:
        self._session_id   = session_id
        self._peer_id      = peer_model_id
        self._threshold    = warp_threshold
        self._on_flush     = on_flush
        self._max_buffer   = max_buffer
        self._state        = SessionState.INIT
        self._warp_score   = 0.0
        self._payload_buf: Deque[str] = deque(maxlen=max_buffer)
        self._event_log:   List[SessionEvent] = []

    # ------------------------------------------------------------------
    # Public state transitions
    # ------------------------------------------------------------------

    def activate(self) -> None:
        """Transition INIT -> ACTIVE after successful HELLO_CONFIRM.

        Raises:
            SessionStateError: If not in INIT state.
        """
        self._require(SessionState.INIT, "activate")
        self._transition(SessionState.ACTIVE, "handshake complete")

    def complete_flush(self) -> None:
        """Transition FLUSHING -> RESYNC when Entropy Flush is done.

        Raises:
            SessionStateError: If not in FLUSHING state.
        """
        self._require(SessionState.FLUSHING, "complete_flush")
        self._transition(SessionState.RESYNC, "entropy flush complete")

    def reactivate(self) -> None:
        """Transition RESYNC -> ACTIVE after a clean re-handshake.

        Resets Warp Score and clears the payload buffer.

        Raises:
            SessionStateError: If not in RESYNC state.
        """
        self._require(SessionState.RESYNC, "reactivate")
        self._warp_score = 0.0
        self._payload_buf.clear()
        self._transition(SessionState.ACTIVE, "re-handshake complete")

    def close(self) -> None:
        """Transition to CLOSED from any non-CLOSED state."""
        if self._state != SessionState.CLOSED:
            self._transition(SessionState.CLOSED, "session closed")

    # ------------------------------------------------------------------
    # Main processing method
    # ------------------------------------------------------------------

    def process_decision(
        self,
        decision: PolicyDecision,
        now: Optional[int] = None,
    ) -> bool:
        """Update session state based on a policy decision.

        Call this method for every inbound payload after evaluating it
        with the PolicyEngine. Returns False if the payload should not
        be processed (DENY or quarantined session).

        Args:
            decision: The PolicyDecision from PolicyEngine.evaluate().
            now:      Timestamp. Defaults to current time.

        Returns:
            True if the payload is permitted; False if denied or quarantined.

        Raises:
            SessionQuarantineError: If the session is in QUARANTINE/FLUSHING/RESYNC.
        """
        now = now if now is not None else int(time.time())

        if self._state in (
            SessionState.QUARANTINE,
            SessionState.FLUSHING,
            SessionState.RESYNC,
            SessionState.CLOSED,
        ):
            raise SessionQuarantineError(
                f"Session in {self._state.value}; no payloads accepted"
            )

        # Track payload for potential flush
        if decision.payload_hash:
            self._payload_buf.append(decision.payload_hash)

        # Accumulate Warp Score
        if decision.action == PolicyAction.DENY:
            self._warp_score += _WARP_ON_DENY
        elif decision.action == PolicyAction.FLAG:
            self._warp_score += _WARP_ON_FLAG
        else:
            self._warp_score = max(0.0, self._warp_score + _WARP_ON_ALLOW)

        self._log(SessionEvent(
            timestamp=now,
            event_type="DECISION",
            payload_hash=decision.payload_hash,
            detail=(
                f"action={decision.action.value} "
                f"rule={decision.matched_rule_id} "
                f"warp_score={self._warp_score:.2f}"
            ),
        ))

        # Check quarantine threshold before state transitions
        if self._warp_score >= self._threshold:
            self._transition(SessionState.QUARANTINE, "warp threshold exceeded")
            self._initiate_flush(now)
            return False

        # State machine transitions based on action
        if self._state == SessionState.ACTIVE and decision.action == PolicyAction.DENY:
            self._transition(SessionState.SUSPECT, "first DENY received")
        elif self._state == SessionState.SUSPECT and self._warp_score < 1.0:
            self._transition(SessionState.ACTIVE, "warp score decayed")

        return decision.action != PolicyAction.DENY

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def warp_score(self) -> float:
        return self._warp_score

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def peer_model_id(self) -> str:
        return self._peer_id

    @property
    def event_log(self) -> List[SessionEvent]:
        return list(self._event_log)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _require(self, expected: SessionState, operation: str) -> None:
        if self._state != expected:
            raise SessionStateError(operation, self._state.value)

    def _transition(self, next_state: SessionState, reason: str) -> None:
        detail = f"{self._state.value} -> {next_state.value} ({reason})"
        self._state = next_state
        self._log(SessionEvent(
            timestamp=int(time.time()),
            event_type="STATE_CHANGE",
            payload_hash="",
            detail=detail,
        ))

    def _initiate_flush(self, now: int) -> None:
        """Execute Entropy Flush: purge buffer, transition to FLUSHING, fire callback."""
        self._transition(SessionState.FLUSHING, "entropy flush initiated")

        incident_id = sha256_hex(self._session_id + str(now))
        tainted = list(self._payload_buf)
        self._payload_buf.clear()

        self._log(SessionEvent(
            timestamp=now,
            event_type="FLUSH",
            payload_hash="",
            detail=f"incident={incident_id} tainted_count={len(tainted)}",
        ))

        if self._on_flush:
            self._on_flush(self._session_id, incident_id, tainted)

    def _log(self, event: SessionEvent) -> None:
        self._event_log.append(event)

    def __repr__(self) -> str:
        return (
            f"Session(peer={self._peer_id!r}, "
            f"state={self._state.value}, "
            f"warp={self._warp_score:.2f})"
        )
