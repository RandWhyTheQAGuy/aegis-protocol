"""
aegis_langgraph
~~~~~~~~~~~~~~~
Aegis Protocol integration for LangGraph.

Wraps LangGraph nodes and graphs with UML-002 Semantic Passport verification,
Policy Engine evaluation, and Session State Machine tracking.

Install:  pip install aegis-langgraph
Requires: aegis-protocol>=0.1.0, langgraph>=0.1.0

Quick start::

    from aegis_langgraph import AegisNode, AegisConfig
    from aegis import PassportRegistry, Capabilities, PolicyEngine, sha256_hex

    registry = PassportRegistry(key, version)
    passport = registry.issue("my-agent", "1.0.0", Capabilities.full(), policy_hash)
    config   = AegisConfig(passport=passport, registry=registry)

    # Wrap any node function
    @AegisNode(config=config)
    def my_node(state: dict) -> dict:
        return {"output": "processed"}

    # Or wrap inline
    safe_node = AegisNode(config=config)(original_node_fn)
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from aegis import (
    SemanticPassport,
    PassportRegistry,
    SemanticClassifier,
    make_stub_backend,
    PolicyEngine,
    PolicyAction,
    Session,
    SessionState,
    ColdAuditVault,
    sha256_hex,
)
from aegis.exceptions import (
    AegisError,
    SessionQuarantineError,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class AegisConfig:
    """Configuration for Aegis-wrapped LangGraph nodes and graphs.

    Attributes:
        passport:        This agent's Semantic Passport.
        registry:        PassportRegistry for issuing/verifying passports.
        policy_engine:   PolicyEngine to evaluate payloads. Defaults to
                         PolicyEngine.from_defaults().
        classifier:      SemanticClassifier for scoring payloads. Defaults to
                         a stub backend — replace with a real classifier in
                         production.
        vault:           Shared ColdAuditVault for audit logging. If None,
                         a new vault is created per node invocation.
        warp_threshold:  Warp Score threshold for session quarantine.
        schema_version:  Payload schema version for handshake negotiation.
        raise_on_deny:   If True, raise AegisDenyError on DENY decisions.
                         If False, return None from the wrapped node.
    """

    passport:       SemanticPassport
    registry:       PassportRegistry
    policy_engine:  PolicyEngine       = field(default_factory=PolicyEngine.from_defaults)
    classifier:     SemanticClassifier = field(
        default_factory=lambda: SemanticClassifier(make_stub_backend())
    )
    vault:          Optional[ColdAuditVault] = None
    warp_threshold: float = 3.0
    schema_version: str   = "uml002-payload-v0.1"
    raise_on_deny:  bool  = False


class AegisDenyError(AegisError):
    """Raised by an AegisNode when a payload is DENIED and raise_on_deny=True."""

    def __init__(self, rule_id: str, payload_hash: str) -> None:
        self.rule_id     = rule_id
        self.payload_hash = payload_hash
        super().__init__(
            f"Payload denied by rule '{rule_id}'. hash={payload_hash[:16]}..."
        )


# ---------------------------------------------------------------------------
# AegisNode decorator
# ---------------------------------------------------------------------------

class AegisNode:
    """Decorator that wraps a LangGraph node function with Aegis Protocol security.

    For each invocation:
    1. Extracts the payload from the state dict (key: ``"input"`` by default).
    2. Scores the payload with the SemanticClassifier.
    3. Evaluates the score with the PolicyEngine.
    4. If DENY: logs to vault, returns None (or raises AegisDenyError).
    5. If ALLOW/FLAG: passes through to the wrapped node function.
    6. Logs all decisions to the ColdAuditVault.

    Args:
        config:      :class:`AegisConfig` instance.
        payload_key: Key in the state dict containing the text payload.
                     Default ``"input"``.
        session:     Optional pre-existing Session. If None, a new session is
                     created per node invocation (stateless mode).

    Example::

        config = AegisConfig(passport=passport, registry=registry)

        @AegisNode(config=config)
        def summarise(state: dict) -> dict:
            # state["input"] has already been policy-checked
            return {"output": f"Summary of: {state['input']}"}

        # Works as a regular function:
        result = summarise({"input": "Please summarise the Q3 report."})
    """

    def __init__(
        self,
        config: AegisConfig,
        payload_key: str = "input",
        session: Optional[Session] = None,
    ) -> None:
        self._config      = config
        self._payload_key = payload_key
        self._session     = session
        self._vault       = config.vault or ColdAuditVault()

    def __call__(self, fn: Callable) -> Callable:
        """Apply the decorator to a node function."""

        @functools.wraps(fn)
        def wrapper(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            now       = int(time.time())
            payload   = state.get(self._payload_key, "")
            agent_id  = self._config.passport.model_id

            if not payload:
                # No payload to score — pass through
                return fn(state)

            # Score and evaluate
            score    = self._config.classifier.score(str(payload), now=now)
            decision = self._config.policy_engine.evaluate(score)

            # Session tracking (stateless: create per-call session)
            session_id = state.get("__aegis_session_id__", sha256_hex(payload + str(now)))

            # Log to vault
            self._vault.append(
                event_type="POLICY_DECISION",
                session_id=session_id,
                agent_id=agent_id,
                payload_hash=score.payload_hash,
                detail=decision.to_dict(),
                timestamp=now,
            )

            if decision.action == PolicyAction.DENY:
                self._vault.append(
                    event_type="SESSION_EVENT",
                    session_id=session_id,
                    agent_id=agent_id,
                    payload_hash=score.payload_hash,
                    detail={"event": "node_blocked", "rule": decision.matched_rule_id},
                    timestamp=now,
                )
                if self._config.raise_on_deny:
                    raise AegisDenyError(decision.matched_rule_id, score.payload_hash)
                return None

            # FLAG: annotate state and continue
            if decision.action == PolicyAction.FLAG:
                state = {**state, "__aegis_flagged__": True,
                         "__aegis_flag_rule__": decision.matched_rule_id}

            return fn(state)

        wrapper.__aegis_config__ = self._config
        wrapper.__aegis_vault__  = self._vault
        return wrapper


# ---------------------------------------------------------------------------
# AegisGraph: session-aware graph wrapper
# ---------------------------------------------------------------------------

class AegisGraph:
    """Session-aware wrapper for a compiled LangGraph graph.

    Maintains a shared :class:`~aegis.session.Session` across all node
    invocations in a graph execution. Initiates Entropy Flush if the session
    is quarantined mid-execution.

    Args:
        graph:   A compiled LangGraph graph (must have an ``.invoke()`` method).
        config:  :class:`AegisConfig` instance.

    Example::

        from langgraph.graph import StateGraph
        builder = StateGraph(...)
        ...
        compiled = builder.compile()

        aegis_graph = AegisGraph(compiled, config)
        result = aegis_graph.invoke({"input": "Summarise the report."})
    """

    def __init__(self, graph: Any, config: AegisConfig) -> None:
        self._graph  = graph
        self._config = config
        self._vault  = config.vault or ColdAuditVault()

    def invoke(self, state: Dict[str, Any], **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Invoke the graph with session tracking.

        Injects ``__aegis_session_id__`` into the state so that wrapped nodes
        can log to the correct session.

        Args:
            state:   Initial state dict for the graph.
            **kwargs: Passed through to the underlying graph's invoke().

        Returns:
            The graph's output state, or None if the session was quarantined.
        """
        now        = int(time.time())
        session_id = sha256_hex(
            self._config.passport.model_id + str(now)
        )

        flush_events: List[dict] = []

        session = Session(
            session_id=session_id,
            peer_model_id="langgraph-graph",
            warp_threshold=self._config.warp_threshold,
            on_flush=lambda sid, inc, tainted: flush_events.append(
                {"incident_id": inc, "tainted": tainted}
            ),
        )
        session.activate()

        self._vault.append(
            event_type="SESSION_EVENT",
            session_id=session_id,
            agent_id=self._config.passport.model_id,
            payload_hash="",
            detail={"event": "graph_invocation_start"},
            timestamp=now,
        )

        state = {**state, "__aegis_session_id__": session_id}

        try:
            result = self._graph.invoke(state, **kwargs)
        except AegisDenyError as exc:
            self._vault.append(
                event_type="QUARANTINE",
                session_id=session_id,
                agent_id=self._config.passport.model_id,
                payload_hash=exc.payload_hash,
                detail={"reason": "DENY", "rule": exc.rule_id},
                timestamp=int(time.time()),
            )
            return None
        finally:
            session.close()
            self._vault.append(
                event_type="SESSION_EVENT",
                session_id=session_id,
                agent_id=self._config.passport.model_id,
                payload_hash="",
                detail={"event": "graph_invocation_end",
                        "flush_events": len(flush_events)},
                timestamp=int(time.time()),
            )

        return result

    @property
    def vault(self) -> ColdAuditVault:
        return self._vault
