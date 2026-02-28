"""
aegis_protocol.session
--------------
Session state machine: INIT -> ACTIVE -> SUSPECT -> QUARANTINE -> FLUSHING -> RESYNC -> CLOSED
"""

import enum
import uuid
from typing import Callable, List, Optional

from aegis_protocol.policy import PolicyAction, PolicyDecision


class SessionState(enum.Enum):
    INIT       = "INIT"
    ACTIVE     = "ACTIVE"
    SUSPECT    = "SUSPECT"
    QUARANTINE = "QUARANTINE"
    FLUSHING   = "FLUSHING"
    RESYNC     = "RESYNC"
    CLOSED     = "CLOSED"


def state_str(state: SessionState) -> str:
    return state.value


FlushCallback = Callable[[str, str, List[str]], None]

# Warp score increments per decision action
WARP_DELTA: dict = {
    PolicyAction.ALLOW: -0.1,
    PolicyAction.FLAG:   0.5,
    PolicyAction.DENY:   1.0,
}
WARP_SUSPECT_THRESHOLD:    float = 1.0
WARP_QUARANTINE_THRESHOLD: float = 2.0


class Session:
    """
    Tracks the security state of an active agent session.
    Accumulates a "warp score" to detect anomalous behaviour.
    """

    def __init__(
        self,
        session_id: str,
        model_id: str,
        warp_threshold: float = 3.0,
        on_flush: Optional[FlushCallback] = None,
    ):
        self._session_id   = session_id
        self._model_id     = model_id
        self._threshold    = warp_threshold
        self._on_flush     = on_flush
        self._state        = SessionState.INIT
        self._warp         = 0.0
        self._tainted:     List[str] = []
        self._incident_id: str = ""

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def state(self) -> SessionState:
        return self._state

    def warp_score(self) -> float:
        return self._warp

    def session_id(self) -> str:
        return self._session_id

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def activate(self) -> None:
        self._require_state(SessionState.INIT)
        self._state = SessionState.ACTIVE

    def close(self) -> None:
        self._state = SessionState.CLOSED

    def reactivate(self) -> None:
        self._require_state(SessionState.RESYNC)
        self._state = SessionState.ACTIVE
        self._warp = 0.0
        self._tainted.clear()

    def complete_flush(self) -> None:
        self._require_state(SessionState.FLUSHING)
        if self._on_flush:
            self._on_flush(self._session_id, self._incident_id, list(self._tainted))
        self._state = SessionState.RESYNC

    # ------------------------------------------------------------------
    # Decision processing
    # ------------------------------------------------------------------

    def process_decision(self, decision: PolicyDecision, now: int) -> bool:
        """
        Apply a policy decision to the session.
        Returns True if the payload is allowed, False otherwise.
        """
        if self._state not in (SessionState.ACTIVE, SessionState.SUSPECT,
                               SessionState.QUARANTINE):
            return False

        allowed = decision.action == PolicyAction.ALLOW
        delta = WARP_DELTA.get(decision.action, 0.0)
        self._warp = max(0.0, self._warp + delta)

        if not allowed and decision.matched_rule_id:
            self._tainted.append(decision.matched_rule_id)

        self._advance_state()
        return allowed

    def _advance_state(self) -> None:
        if self._warp >= self._threshold:
            self._incident_id = str(uuid.uuid4())
            self._state = SessionState.FLUSHING
        elif self._warp >= WARP_QUARANTINE_THRESHOLD:
            self._state = SessionState.QUARANTINE
        elif self._warp >= WARP_SUSPECT_THRESHOLD:
            self._state = SessionState.SUSPECT
        else:
            if self._state in (SessionState.SUSPECT, SessionState.QUARANTINE):
                self._state = SessionState.ACTIVE

    def _require_state(self, expected: SessionState) -> None:
        if self._state != expected:
            raise RuntimeError(
                f"Expected state {expected.value} but current state is {self._state.value}"
            )
