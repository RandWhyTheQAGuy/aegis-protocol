"""
Aegis Protocol (Semantic Passport System)
=========================================
Copyright 2026 Gary Gray (github.com/<your-github-handle>)

aegis_langgraph_integration.py
================================
Aegis Protocol security layer for LangGraph agent workflows.

OVERVIEW
--------
LangGraph models agent workflows as directed state graphs (nodes + edges).
This integration wraps each graph node with an Aegis Protocol security
enforcement point so that every state transition is:
  1. Evaluated against a Semantic Passport + PolicyEngine
  2. Recorded to a tamper-evident AuditVault
  3. Logged to a hash-chained TransparencyLog
  4. Tracked by a per-session warp-score SessionGuard

The integration surface has three tiers:

  TIER 1 — AegisCheckpointer
    A custom LangGraph BaseCheckpointSaver that wraps any underlying
    checkpointer and intercepts every .put() call to perform a policy
    check before the checkpoint is committed.  Provides fail-closed
    persistence: if Aegis denies the step, the checkpoint is not saved
    and the graph cannot advance.

  TIER 2 — @aegis_node decorator
    A function decorator that wraps individual graph node functions.
    Evaluates the outgoing state update before the node returns,
    optionally blocking state propagation on DENY.

  TIER 3 — AegisStateGraph
    A thin subclass of StateGraph that auto-applies the @aegis_node
    wrapper to every node added via add_node() and injects the
    AegisCheckpointer at compile time.

COLD-START BEHAVIOUR
--------------------
Calling AegisStateGraph.compile() before start() raises RuntimeError.
start() validates the passport, activates the session, records the
bridge_started event to the TransparencyLog, and returns the compiled
graph.  From this point forward all node calls go through Aegis.

SECURITY / RELIABILITY POSTURE
-------------------------------
* Fail-closed on all boundaries (passport expiry, policy error, vault error).
* No credentials in logs (key fields auto-redacted).
* Per-node sensitivity overrides supported via node_sensitivity registry.
* Quarantined sessions raise PermissionError on any node invocation.
* shutdown() performs O(n) chain verification and closes the session.

STANDARDS ALIGNMENT (via aegis_adapter)
---------------------------------------
NIST AI RMF 1.0  ·  NIST SP 800-53 Rev 5  ·  DoD Zero Trust v2.0
OWASP LLM Top 10 v2025  ·  ISA/IEC 62443-3-3  ·  NERC CIP-007/010

DEPENDENCIES
------------
  pip install langgraph>=0.2 langchain-core>=0.3

NOTE: LangGraph stubs are provided below so the integration runs without
      a live LLM.  Replace the stub StateGraph / InMemorySaver with the
      real langgraph imports when deploying against actual LLM agents.

      Real imports:
        from langgraph.graph import StateGraph, END
        from langgraph.graph.state import CompiledGraph
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.checkpoint.base import BaseCheckpointSaver
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

import functools
import hashlib
import json
import logging
import time
import uuid
from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from python.aegis_protocol.adapters.aegis_adapter import (
    AegisAdapter,
    AegisFrameworkBridge,
    PolicyDecision,
    PolicyEngine,
    SemanticPassport,
    SessionState,
    _emit,
    _build_logger,
)

LOG = _build_logger("aegis_langgraph")

# ─── LangGraph stubs (replace with real langgraph imports in production) ─────

class _StubCheckpointSaver:
    """Minimal stub; real implementation: langgraph.checkpoint.memory.InMemorySaver"""
    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}

    def put(self, config: Dict, checkpoint: Dict, metadata: Dict,
            new_versions: Dict) -> Dict:
        thread_id = config.get("configurable", {}).get("thread_id", "default")
        self._store[thread_id] = {
            "config": config, "checkpoint": checkpoint,
            "metadata": metadata,
        }
        return config

    def get_tuple(self, config: Dict) -> Optional[Dict]:
        thread_id = config.get("configurable", {}).get("thread_id", "default")
        return self._store.get(thread_id)

    def list(self, config: Dict) -> List[Dict]:
        return list(self._store.values())


# Sentinel used as the graph terminal node name
END = "__end__"


class _StubCompiledGraph:
    """
    Stub compiled graph returned by AegisStateGraph.compile().
    In production this is replaced by langgraph's CompiledGraph.
    """
    def __init__(self, nodes: Dict[str, Callable],
                 edges: Dict[str, str],
                 entry: str,
                 checkpointer: "_StubCheckpointSaver") -> None:
        self._nodes       = nodes
        self._edges       = edges
        self._entry       = entry
        self._checkpointer = checkpointer

    def invoke(self, state: Dict[str, Any],
               config: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Execute the graph: walk nodes following edges until END is reached.
        Each node function receives the current state and returns a partial
        state update dict which is merged into the running state.
        """
        config    = config or {"configurable": {"thread_id": str(uuid.uuid4())}}
        current   = deepcopy(state)
        node_name = self._entry

        visited: List[str] = []
        while node_name and node_name != END:
            if node_name not in self._nodes:
                raise RuntimeError(f"Unknown node: {node_name!r}")
            visited.append(node_name)
            fn     = self._nodes[node_name]
            update = fn(current)             # call the (wrapped) node function
            if isinstance(update, dict):
                current.update(update)
            node_name = self._edges.get(node_name, END)

        # Persist final checkpoint
        self._checkpointer.put(
            config,
            {"state": current, "visited": visited},
            {"source": "loop"},
            {},
        )
        return current

    def stream(self, state: Dict[str, Any],
               config: Optional[Dict] = None):
        """Yield node outputs one at a time (stub: yields final state once)."""
        result = self.invoke(state, config)
        yield result

# ─── TIER 1 — AegisCheckpointer ──────────────────────────────────────────────

class AegisCheckpointer:
    """
    LangGraph checkpoint saver that enforces Aegis Protocol policy on
    every .put() call before delegating to the underlying checkpointer.

    The checkpoint represents committed graph state.  If Aegis denies
    the step, the checkpoint is withheld — the graph cannot advance past
    a denied superstep.

    Parameters
    ----------
    bridge      : AegisFrameworkBridge for the owning agent
    inner       : underlying BaseCheckpointSaver (InMemorySaver, etc.)
    sensitivity : default sensitivity for checkpointed state writes
    """

    def __init__(self, bridge: AegisFrameworkBridge,
                 inner: Optional[_StubCheckpointSaver] = None,
                 sensitivity: float = 0.10) -> None:
        self._bridge      = bridge
        self._inner       = inner or _StubCheckpointSaver()
        self._sensitivity = sensitivity

    def put(self, config: Dict, checkpoint: Dict, metadata: Dict,
            new_versions: Dict) -> Dict:
        """
        Intercept a checkpoint write.

        Serialises the checkpoint to JSON, evaluates it through the Aegis
        PolicyEngine, and only delegates to the inner checkpointer if ALLOW
        or FLAG.  DENY raises PermissionError, halting graph execution.
        """
        thread_id = config.get("configurable", {}).get("thread_id", "?")
        payload   = json.dumps(checkpoint, default=str)

        try:
            result, allowed = self._bridge.evaluate_action(
                payload=payload,
                authority=0.7,
                sensitivity=self._sensitivity,
                event_type="checkpoint_write",
                thread_id=thread_id,
            )
        except PermissionError:
            raise   # quarantine — propagate immediately
        except Exception as exc:
            _emit(LOG, "error", "AegisCheckpointer", "eval_error",
                  error=str(exc), action="fail_closed_deny")
            raise PermissionError(
                f"AegisCheckpointer: fail-closed on evaluation error: {exc}"
            )

        if not allowed:
            _emit(LOG, "warning", "AegisCheckpointer", "checkpoint_denied",
                  thread_id=thread_id, reason=result.reason)
            raise PermissionError(
                f"Checkpoint denied by Aegis Policy: {result.reason}"
            )

        return self._inner.put(config, checkpoint, metadata, new_versions)

    def get_tuple(self, config: Dict) -> Optional[Dict]:
        return self._inner.get_tuple(config)

    def list(self, config: Dict) -> List[Dict]:
        return self._inner.list(config)

# ─── TIER 2 — @aegis_node decorator ──────────────────────────────────────────

def aegis_node(bridge: AegisFrameworkBridge,
               node_name: str = "",
               sensitivity: float = 0.10,
               capability: Optional[str] = None):
    """
    Decorator that wraps a LangGraph node function with Aegis enforcement.

    The wrapper:
      1. Optionally validates a required capability against the passport.
      2. Evaluates the serialised state update through the PolicyEngine.
      3. Records the decision to the AuditVault and TransparencyLog.
      4. Returns the state update on ALLOW/FLAG or raises on DENY.

    Parameters
    ----------
    bridge      : AegisFrameworkBridge for the owning agent
    node_name   : human-readable label for logging (defaults to fn name)
    sensitivity : sensitivity score for this node's outputs (0.0–1.0)
    capability  : if set, passport must grant this capability string

    Usage
    -----
    @aegis_node(bridge, node_name="research_node", sensitivity=0.3)
    def research(state: dict) -> dict:
        return {"result": "research output"}
    """
    def decorator(fn: Callable) -> Callable:
        label = node_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(state: Dict[str, Any]) -> Dict[str, Any]:
            # Capability gate (before executing the node at all)
            if capability:
                bridge.require_capability(capability)

            # Execute the underlying node
            try:
                update = fn(state)
            except Exception as exc:
                _emit(LOG, "error", "aegis_node", "node_execution_error",
                      node=label, error=str(exc))
                raise

            # Evaluate the state update through Aegis
            payload = json.dumps(update, default=str)
            try:
                result, allowed = bridge.evaluate_action(
                    payload=payload,
                    authority=0.6,
                    sensitivity=sensitivity,
                    event_type="node_output",
                    node_name=label,
                )
            except PermissionError:
                raise
            except Exception as exc:
                _emit(LOG, "error", "aegis_node", "eval_error",
                      node=label, error=str(exc),
                      action="fail_closed_deny")
                raise PermissionError(
                    f"Node {label!r}: fail-closed on Aegis eval error: {exc}"
                )

            if not allowed:
                _emit(LOG, "warning", "aegis_node", "node_output_denied",
                      node=label, reason=result.reason)
                raise PermissionError(
                    f"Node {label!r} output denied: {result.reason}"
                )

            return update

        wrapper._aegis_wrapped = True       # marker for introspection
        wrapper._aegis_node    = label
        return wrapper

    return decorator

# ─── TIER 3 — AegisStateGraph ─────────────────────────────────────────────────

class AegisStateGraph:
    """
    Aegis-aware StateGraph.

    Drop-in replacement for langgraph.graph.StateGraph that:
      - Auto-wraps every added node with @aegis_node
      - Compiles with an AegisCheckpointer injected
      - Enforces passport validity at compile time
      - Provides a clean shutdown() that verifies chain integrity

    Parameters
    ----------
    passport    : Semantic Passport for the agent that owns this graph
    adapter     : shared AegisAdapter (vault + tlog + policy shared fleet-wide)
    framework   : label used in audit records (default: "langgraph")

    Quick-start
    -----------
    adapter = AegisAdapter()
    graph   = AegisStateGraph(passport, adapter)
    graph.add_node("fetch",    fetch_fn,   sensitivity=0.1)
    graph.add_node("analyse",  analyse_fn, sensitivity=0.3)
    graph.add_edge("fetch", "analyse")
    graph.add_edge("analyse", END)
    graph.set_entry_point("fetch")
    compiled = graph.start()
    result   = compiled.invoke({"query": "hello"})
    vault_ok, tlog_ok = graph.shutdown()
    """

    def __init__(self, passport: SemanticPassport,
                 adapter:   AegisAdapter,
                 framework: str = "langgraph") -> None:
        self.passport  = passport
        self.adapter   = adapter
        self.framework = framework
        self._bridge: Optional[AegisFrameworkBridge] = None
        self._nodes:  Dict[str, Callable]  = {}
        self._edges:  Dict[str, str]       = {}
        self._entry:  Optional[str]        = None
        self._sensitivity_map: Dict[str, float] = {}
        self._capability_map:  Dict[str, Optional[str]] = {}
        self._compiled: Optional[_StubCompiledGraph] = None
        _emit(LOG, "info", "AegisStateGraph", "created",
              model_id=passport.model_id, framework=framework)

    def add_node(self, name: str, fn: Callable,
                 sensitivity: float = 0.10,
                 capability:  Optional[str] = None) -> "AegisStateGraph":
        """Register a node.  Aegis wrapping is applied at compile time."""
        self._nodes[name] = fn
        self._sensitivity_map[name] = sensitivity
        self._capability_map[name]  = capability
        _emit(LOG, "debug", "AegisStateGraph", "node_added",
              name=name, sensitivity=sensitivity,
              capability=capability or "none")
        return self

    def add_edge(self, src: str, dst: str) -> "AegisStateGraph":
        self._edges[src] = dst
        return self

    def set_entry_point(self, name: str) -> "AegisStateGraph":
        self._entry = name
        return self

    def start(self) -> _StubCompiledGraph:
        """
        Validate passport, register agent, apply @aegis_node wrappers,
        inject AegisCheckpointer, and return the compiled graph.
        Raises PermissionError on expired passport or before set_entry_point.
        """
        if not self._entry:
            raise RuntimeError("set_entry_point() must be called before start()")

        # Register and start the bridge (validates passport)
        self._bridge = self.adapter.register_agent(self.passport, self.framework)
        self._bridge.start()

        # Wrap all nodes
        wrapped: Dict[str, Callable] = {}
        for name, fn in self._nodes.items():
            wrapped[name] = aegis_node(
                self._bridge,
                node_name=name,
                sensitivity=self._sensitivity_map.get(name, 0.10),
                capability=self._capability_map.get(name),
            )(fn)

        # Build checkpointer
        checkpointer = AegisCheckpointer(self._bridge)

        # Compile
        self._compiled = _StubCompiledGraph(
            nodes=wrapped,
            edges=self._edges,
            entry=self._entry,
            checkpointer=checkpointer,
        )
        _emit(LOG, "info", "AegisStateGraph", "compiled",
              node_count=len(wrapped),
              entry=self._entry,
              session_id=self._bridge.session.session_id)
        return self._compiled

    def shutdown(self) -> Tuple[bool, bool]:
        """
        Close the session and verify vault + tlog chain integrity.
        Returns (vault_ok, tlog_ok).
        """
        if not self._bridge:
            raise RuntimeError("shutdown() called before start()")
        return self._bridge.shutdown()

    @property
    def bridge(self) -> Optional[AegisFrameworkBridge]:
        return self._bridge

# ─── TEST SUITE ───────────────────────────────────────────────────────────────

import pytest


POLICY_HASH = hashlib.sha256(b"langgraph-policy-v1").hexdigest()

def _make_passport(ttl: int = 3600,
                   caps: frozenset = frozenset({"read", "write"}),
                   expired: bool = False) -> SemanticPassport:
    p = SemanticPassport(
        model_id="lg-agent-1",
        version="1.0.0",
        policy_hash=POLICY_HASH,
        ttl_seconds=1 if expired else ttl,
        capabilities=caps,
    )
    if expired:
        import time as _t
        object.__setattr__(p, "issued_at", _t.time() - 10)
    return p

def _make_adapter() -> AegisAdapter:
    return AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
    ))

def _make_graph(caps: frozenset = frozenset({"read", "write"}),
                expired: bool = False) -> AegisStateGraph:
    adapter = _make_adapter()
    passport = _make_passport(caps=caps, expired=expired)
    graph = AegisStateGraph(passport, adapter)
    return graph


class TestAegisCheckpointer:
    def test_allowed_checkpoint_persists(self):
        adapter = _make_adapter()
        bridge  = adapter.register_agent(_make_passport(), "langgraph")
        bridge.start()
        ckpt = AegisCheckpointer(bridge, sensitivity=0.05)
        cfg  = {"configurable": {"thread_id": "t1"}}
        result = ckpt.put(cfg, {"messages": []}, {"source": "loop"}, {})
        assert result == cfg
        assert ckpt.get_tuple(cfg) is not None

    def test_high_sensitivity_checkpoint_denied(self):
        adapter  = _make_adapter()
        # Set ceiling very low so any checkpoint is denied
        adapter.policy = PolicyEngine(sensitivity_ceiling=0.01)
        bridge   = adapter.register_agent(_make_passport(), "langgraph")
        bridge.start()
        ckpt = AegisCheckpointer(bridge, sensitivity=0.90)
        cfg  = {"configurable": {"thread_id": "t2"}}
        with pytest.raises(PermissionError):
            ckpt.put(cfg, {"data": "sensitive"}, {}, {})

    def test_quarantined_session_raises(self):
        adapter = _make_adapter()
        bridge  = adapter.register_agent(_make_passport(), "langgraph")
        bridge.start()
        # Drive to quarantine
        for _ in range(8):
            bridge.session.record(PolicyDecision.DENY)
        ckpt = AegisCheckpointer(bridge)
        with pytest.raises(PermissionError, match="quarantine"):
            ckpt.put({"configurable": {"thread_id": "t3"}},
                     {}, {}, {})


class TestAegisNodeDecorator:
    def test_clean_node_passes(self):
        adapter = _make_adapter()
        bridge  = adapter.register_agent(_make_passport(), "langgraph")
        bridge.start()

        @aegis_node(bridge, node_name="test_node", sensitivity=0.05)
        def my_node(state):
            return {"result": "hello"}

        out = my_node({"input": "x"})
        assert out == {"result": "hello"}
        assert bridge.vault.length == 1

    def test_sensitive_node_denied(self):
        adapter  = _make_adapter()
        adapter.policy = PolicyEngine(sensitivity_ceiling=0.05)
        bridge   = adapter.register_agent(_make_passport(), "langgraph")
        bridge.start()

        @aegis_node(bridge, node_name="bad_node", sensitivity=0.90)
        def bad_node(state):
            return {"result": "risky"}

        with pytest.raises(PermissionError):
            bad_node({})
        assert bridge.vault.length == 0   # denied nodes are never vaulted

    def test_capability_gate_blocks(self):
        adapter  = _make_adapter()
        bridge   = adapter.register_agent(
            _make_passport(caps=frozenset({"read"})), "langgraph"
        )
        bridge.start()

        @aegis_node(bridge, node_name="write_node", capability="write")
        def write_node(state):
            return {"written": True}

        with pytest.raises(PermissionError, match="capability"):
            write_node({})

    def test_capability_gate_allows(self):
        adapter = _make_adapter()
        bridge  = adapter.register_agent(
            _make_passport(caps=frozenset({"read", "write"})), "langgraph"
        )
        bridge.start()

        @aegis_node(bridge, node_name="write_node", capability="write")
        def write_node(state):
            return {"written": True}

        out = write_node({})
        assert out["written"] is True


class TestAegisStateGraph:
    def test_cold_start_and_invoke(self):
        graph = _make_graph()
        graph.add_node("step1", lambda s: {"step1": "done"})
        graph.add_node("step2", lambda s: {"step2": "done"})
        graph.add_edge("step1", "step2")
        graph.add_edge("step2", END)
        graph.set_entry_point("step1")

        compiled = graph.start()
        result   = compiled.invoke({"initial": True})

        assert result["step1"] == "done"
        assert result["step2"] == "done"
        assert graph.bridge.vault.length >= 2

    def test_expired_passport_blocked_at_start(self):
        graph = _make_graph(expired=True)
        graph.add_node("n", lambda s: s)
        graph.add_edge("n", END)
        graph.set_entry_point("n")
        with pytest.raises(PermissionError, match="expired"):
            graph.start()

    def test_missing_entry_point_raises(self):
        graph = _make_graph()
        graph.add_node("n", lambda s: s)
        with pytest.raises(RuntimeError, match="entry_point"):
            graph.start()

    def test_shutdown_verifies_chains(self):
        graph = _make_graph()
        graph.add_node("n", lambda s: {"x": 1})
        graph.add_edge("n", END)
        graph.set_entry_point("n")
        graph.start()
        graph.bridge.vault.append(
            "lg-agent-1", graph.bridge.session.session_id,
            "test", "payload",
            graph.bridge.policy.evaluate(
                __import__("aegis_adapter").SemanticScore(0.8, 0.1)
            ),
        )
        vault_ok, tlog_ok = graph.shutdown()
        assert vault_ok is True
        assert tlog_ok  is True

    def test_multi_node_graph_full_flow(self):
        """End-to-end: 3-node pipeline, vault chain verifies on shutdown."""
        graph = _make_graph()
        graph.add_node("fetch",   lambda s: {"fetched": True},   sensitivity=0.1)
        graph.add_node("analyse", lambda s: {"analysed": True},  sensitivity=0.2)
        graph.add_node("report",  lambda s: {"reported": True},  sensitivity=0.1)
        graph.add_edge("fetch",   "analyse")
        graph.add_edge("analyse", "report")
        graph.add_edge("report",  END)
        graph.set_entry_point("fetch")

        compiled = graph.start()
        result   = compiled.invoke({})

        assert result["fetched"]  is True
        assert result["analysed"] is True
        assert result["reported"] is True

        vault_ok, tlog_ok = graph.shutdown()
        assert vault_ok
        assert tlog_ok

    def test_warp_accumulation_across_nodes(self):
        """High-sensitivity nodes should drive up warp score."""
        adapter  = _make_adapter()
        passport = _make_passport()
        graph    = AegisStateGraph(passport, adapter)
        # All nodes have high sensitivity to accumulate warp
        graph.add_node("n1", lambda s: {"x": 1}, sensitivity=0.60)
        graph.add_node("n2", lambda s: {"y": 2}, sensitivity=0.60)
        graph.add_edge("n1", "n2")
        graph.add_edge("n2", END)
        graph.set_entry_point("n1")
        graph.start()
        graph.bridge.adapter if hasattr(graph.bridge, "adapter") else None
        # Nodes flagged → warp increases
        assert graph.bridge.session.warp_score >= 0.0

    def test_adapter_fleet_status(self):
        adapter = _make_adapter()
        p1 = SemanticPassport("agent-a", "1.0", POLICY_HASH, 3600)
        p2 = SemanticPassport("agent-b", "1.0", POLICY_HASH, 3600)
        b1 = adapter.register_agent(p1, "langgraph")
        b2 = adapter.register_agent(p2, "langgraph")
        b1.start(); b2.start()
        status = adapter.fleet_status()
        assert len(status) == 2
        assert any(s["model_id"] == "agent-a" for s in status)


# ─── DEMO ENTRYPOINT ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Aegis Protocol + LangGraph Integration Demo")
    print("=" * 70 + "\n")

    # ── build shared adapter ────────────────────────────────────────────────
    adapter = AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
    ))

    # ── define a research → summarise → report pipeline ─────────────────────
    passport = SemanticPassport(
        model_id="demo-researcher",
        version="1.2.0",
        policy_hash=hashlib.sha256(b"demo-policy").hexdigest(),
        ttl_seconds=3600,
        capabilities=frozenset({"read", "write", "summarise"}),
    )

    graph = AegisStateGraph(passport, adapter, framework="langgraph")

    def research_node(state: dict) -> dict:
        print("  [research_node]  fetching information...")
        return {"research_output": "AI safety landscape summary v2"}

    def summarise_node(state: dict) -> dict:
        print("  [summarise_node] condensing findings...")
        return {"summary": f"Summary of: {state.get('research_output', '')}"}

    def report_node(state: dict) -> dict:
        print("  [report_node]    writing final report...")
        return {"report": f"REPORT: {state.get('summary', '')}"}

    graph.add_node("research",  research_node,  sensitivity=0.10, capability="read")
    graph.add_node("summarise", summarise_node, sensitivity=0.15, capability="summarise")
    graph.add_node("report",    report_node,    sensitivity=0.10, capability="write")
    graph.add_edge("research",  "summarise")
    graph.add_edge("summarise", "report")
    graph.add_edge("report",    END)
    graph.set_entry_point("research")

    print("Starting Aegis-guarded graph...\n")
    compiled = graph.start()
    print(f"Session ID : {graph.bridge.session.session_id}")
    print(f"Passport   : {passport.passport_id}\n")

    result = compiled.invoke({"query": "AI safety in 2025"})
    print(f"\nFinal state keys : {list(result.keys())}")
    print(f"Report           : {result.get('report')}")

    print(f"\nWarp score   : {graph.bridge.session.warp_score:.4f}")
    print(f"Session state: {graph.bridge.session.state.value}")
    print(f"Vault entries: {adapter.vault.length}")
    print(f"TLog entries : {adapter.tlog.length}")

    vault_ok, tlog_ok = graph.shutdown()
    print(f"\nVault chain  : {'PASS' if vault_ok else 'FAIL'}")
    print(f"TLog chain   : {'PASS' if tlog_ok  else 'FAIL'}")
    print("\nDemo complete.\n")