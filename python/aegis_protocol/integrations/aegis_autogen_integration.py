"""
Aegis Protocol (Semantic Passport System)
=========================================
Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
SPDX-License-Identifier: Apache-2.0

aegis_autogen_integration.py
==============================
Aegis Protocol security layer for Microsoft AutoGen v0.4 AgentChat.

OVERVIEW
--------
AutoGen v0.4 frames multi-agent collaboration as asynchronous message
passing between BaseChatAgent instances.  This integration wraps the
message lifecycle with Aegis Protocol enforcement at three points:

  TIER 1 — AegisChatAgent (BaseChatAgent subclass)
    Every incoming message and every outgoing response is evaluated
    through the Aegis PolicyEngine before on_messages() executes or
    before the Response is returned.  Fail-closed: any DENY blocks
    the message from reaching the underlying agent logic.

  TIER 2 — AegisMessageInterceptor
    A composable wrapper that can be applied around any existing
    BaseChatAgent without subclassing.  Intercepts on_messages() /
    on_messages_stream() calls, performs Aegis evaluation, and
    delegates to the inner agent only if permitted.

  TIER 3 — AegisGroupChatSecurity
    Fleet-level enforcement for RoundRobinGroupChat / SelectorGroupChat
    scenarios.  Validates passport and session health for every agent
    before the team runs, and produces a consolidated security report
    after termination.

COLD-START BEHAVIOUR
--------------------
AegisChatAgent.start() must be called before run() / run_stream().
AegisGroupChatSecurity.start() validates all registered agents before
the team kicks off.  Any expired passport blocks the entire team.

AUTOGEN v0.4 API NOTES
-----------------------
  BaseChatAgent.on_messages(messages, cancellation_token) → Response
  Response.chat_message : TextMessage | ToolCallSummaryMessage | ...
  TextMessage(content: str, source: str)
  CancellationToken — passed through without modification

DEPENDENCIES
------------
  pip install "autogen-agentchat>=0.4" "autogen-ext[openai]"

NOTE: AutoGen stubs are provided so the integration runs without a live
      LLM.  Replace stub classes with real AutoGen imports:
        from autogen_agentchat.agents import BaseChatAgent, AssistantAgent
        from autogen_agentchat.messages import TextMessage, BaseChatMessage
        from autogen_agentchat.base import Response
        from autogen_core import CancellationToken

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

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from typing import Any, AsyncGenerator, Dict, List, Optional, Sequence, Tuple

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

LOG = _build_logger("aegis_autogen")

# ─── AutoGen v0.4 stubs ────────────────────────────────────────────────────

class CancellationToken:
    """Stub for autogen_core.CancellationToken"""
    def __init__(self) -> None:
        self._cancelled = False
    def cancel(self) -> None:
        self._cancelled = True
    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


class TextMessage:
    """Stub for autogen_agentchat.messages.TextMessage"""
    def __init__(self, content: str, source: str) -> None:
        self.content  = content
        self.source   = source
        self.id       = str(uuid.uuid4())
        self.created_at = time.time()
        self.type     = "TextMessage"

    def to_text(self) -> str:
        return self.content

    def __repr__(self) -> str:
        return f"TextMessage(source={self.source!r}, content={self.content[:60]!r})"


class Response:
    """Stub for autogen_agentchat.base.Response"""
    def __init__(self, chat_message: TextMessage,
                 inner_messages: Optional[List[TextMessage]] = None) -> None:
        self.chat_message    = chat_message
        self.inner_messages  = inner_messages or []


class StopMessage(TextMessage):
    """Stub for autogen_agentchat.messages.StopMessage"""
    def __init__(self, content: str, source: str) -> None:
        super().__init__(content, source)
        self.type = "StopMessage"


class TaskResult:
    """Stub for autogen_agentchat.base.TaskResult"""
    def __init__(self, messages: List[TextMessage], stop_reason: str) -> None:
        self.messages    = messages
        self.stop_reason = stop_reason


# ─── TIER 1 — AegisChatAgent ─────────────────────────────────────────────────

class AegisChatAgent:
    """
    AutoGen BaseChatAgent subclass with Aegis Protocol enforcement.

    Evaluates every inbound message and every outbound response through
    the Aegis PolicyEngine.  Fail-closed on both boundaries:
      - Inbound DENY: message is blocked before reaching agent logic.
      - Outbound DENY: response is suppressed; a quarantine notice is
        returned in its place so the conversation is not silently broken.

    Parameters
    ----------
    name           : agent name (shown in message source field)
    description    : human-readable description
    passport       : Semantic Passport for this agent
    adapter        : shared AegisAdapter (vault + tlog + policy)
    handler        : the underlying async callable that implements the
                     actual agent logic.  Signature:
                       async (messages: List[TextMessage]) -> TextMessage
                     In production replace with AssistantAgent delegation.
    in_sensitivity : sensitivity score applied to inbound message evaluation
    out_sensitivity: sensitivity score applied to outbound response evaluation
    """

    def __init__(self,
                 name:            str,
                 description:     str,
                 passport:        SemanticPassport,
                 adapter:         AegisAdapter,
                 handler:         Any = None,
                 in_sensitivity:  float = 0.10,
                 out_sensitivity: float = 0.15) -> None:
        self.name            = name
        self.description     = description
        self._passport       = passport
        self._adapter        = adapter
        self._handler        = handler
        self._in_sensitivity  = in_sensitivity
        self._out_sensitivity = out_sensitivity
        self._bridge: Optional[AegisFrameworkBridge] = None
        self._message_history: List[TextMessage] = []

        _emit(LOG, "info", "AegisChatAgent", "created",
              name=name, model_id=passport.model_id)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> "AegisChatAgent":
        """Register passport and activate session.  Returns self for chaining."""
        self._bridge = self._adapter.register_agent(
            self._passport, framework="autogen"
        )
        self._bridge.start()
        _emit(LOG, "info", "AegisChatAgent", "started",
              name=self.name,
              session_id=self._bridge.session.session_id)
        return self

    def shutdown(self) -> Tuple[bool, bool]:
        """Close session and verify chains.  Returns (vault_ok, tlog_ok)."""
        if not self._bridge:
            raise RuntimeError("shutdown() called before start()")
        return self._bridge.shutdown()

    # ── AutoGen AgentChat API ─────────────────────────────────────────────────

    async def on_messages(self, messages: Sequence[TextMessage],
                          cancellation_token: CancellationToken
                          ) -> Response:
        """
        AutoGen on_messages() entry point.

        Pipeline:
          1. Evaluate inbound messages through Aegis (fail-closed).
          2. If allowed, delegate to handler or default echo logic.
          3. Evaluate outbound response through Aegis.
          4. Return response or a sanitised denial notice.
        """
        if not self._bridge:
            raise RuntimeError(
                f"Agent {self.name!r}: start() must be called before on_messages()"
            )

        if cancellation_token.is_cancelled:
            _emit(LOG, "info", "AegisChatAgent", "cancelled",
                  name=self.name)
            return Response(
                TextMessage(content="[CANCELLED]", source=self.name)
            )

        # ── 1. Inbound evaluation ────────────────────────────────────────────
        inbound_text = " ".join(m.to_text() for m in messages if messages)
        try:
            in_result, in_allowed = self._bridge.evaluate_action(
                payload=inbound_text,
                authority=0.6,
                sensitivity=self._in_sensitivity,
                event_type="inbound_message",
                agent_name=self.name,
                message_count=len(messages),
            )
        except PermissionError as exc:
            _emit(LOG, "error", "AegisChatAgent", "inbound_quarantine",
                  name=self.name, error=str(exc))
            return Response(
                TextMessage(
                    content=f"[QUARANTINE] {self.name} session is quarantined.",
                    source=self.name,
                )
            )

        if not in_allowed:
            _emit(LOG, "warning", "AegisChatAgent", "inbound_denied",
                  name=self.name, reason=in_result.reason)
            return Response(
                TextMessage(
                    content=f"[DENIED] Message blocked by Aegis: {in_result.reason}",
                    source=self.name,
                )
            )

        # ── 2. Agent handler ─────────────────────────────────────────────────
        self._message_history.extend(messages)
        try:
            if self._handler is not None:
                raw_response: TextMessage = await self._handler(
                    messages, cancellation_token
                )
            else:
                # Default: acknowledge with echo summary
                raw_response = TextMessage(
                    content=f"Agent {self.name} processed: {inbound_text[:120]}",
                    source=self.name,
                )
        except Exception as exc:
            _emit(LOG, "error", "AegisChatAgent", "handler_error",
                  name=self.name, error=str(exc))
            raise

        # ── 3. Outbound evaluation ───────────────────────────────────────────
        try:
            out_result, out_allowed = self._bridge.evaluate_action(
                payload=raw_response.content,
                authority=0.7,
                sensitivity=self._out_sensitivity,
                event_type="outbound_response",
                agent_name=self.name,
            )
        except PermissionError as exc:
            return Response(
                TextMessage(
                    content="[QUARANTINE] Response suppressed; session quarantined.",
                    source=self.name,
                )
            )

        if not out_allowed:
            _emit(LOG, "warning", "AegisChatAgent", "outbound_denied",
                  name=self.name, reason=out_result.reason)
            return Response(
                TextMessage(
                    content=f"[DENIED] Response suppressed: {out_result.reason}",
                    source=self.name,
                )
            )

        _emit(LOG, "info", "AegisChatAgent", "message_processed",
              name=self.name,
              in_decision=in_result.decision.value,
              out_decision=out_result.decision.value,
              warp_score=round(self._bridge.session.warp_score, 4))

        return Response(chat_message=raw_response)

    async def on_messages_stream(self, messages: Sequence[TextMessage],
                                  cancellation_token: CancellationToken
                                  ) -> AsyncGenerator[Any, None]:
        """
        Streaming variant: evaluates on the first message then yields
        the response in one chunk (production impl would chunk tokens).
        """
        response = await self.on_messages(messages, cancellation_token)
        yield response.chat_message
        yield response

    async def on_reset(self, cancellation_token: CancellationToken) -> None:
        """Reset message history but preserve Aegis session state."""
        self._message_history.clear()
        if self._bridge:
            self._bridge.tlog.record(
                self._passport.model_id,
                self._bridge.session.session_id,
                "agent_reset",
                agent_name=self.name,
            )

    @property
    def produced_message_types(self):
        return (TextMessage,)


# ─── TIER 2 — AegisMessageInterceptor ────────────────────────────────────────

class AegisMessageInterceptor:
    """
    Composable Aegis wrapper for any existing AutoGen agent.

    Intercepts on_messages() calls without requiring subclassing.
    Designed for retrofitting Aegis onto pre-existing AssistantAgent
    instances.

    Parameters
    ----------
    inner_agent : any agent with an on_messages() method
    bridge      : pre-configured AegisFrameworkBridge
    in_sensitivity  : inbound message sensitivity
    out_sensitivity : outbound response sensitivity
    """

    def __init__(self, inner_agent: Any,
                 bridge: AegisFrameworkBridge,
                 in_sensitivity:  float = 0.10,
                 out_sensitivity: float = 0.15) -> None:
        self._inner          = inner_agent
        self._bridge         = bridge
        self._in_sensitivity  = in_sensitivity
        self._out_sensitivity = out_sensitivity
        self.name        = getattr(inner_agent, "name", "wrapped_agent")
        self.description = getattr(inner_agent, "description", "")
        _emit(LOG, "info", "AegisMessageInterceptor", "created",
              wrapped=self.name,
              session_id=bridge.session.session_id)

    async def on_messages(self, messages: Sequence[TextMessage],
                          cancellation_token: CancellationToken
                          ) -> Response:
        """
        Intercept: evaluate inbound → delegate → evaluate outbound.
        """
        # Inbound check
        payload = " ".join(m.to_text() for m in messages)
        try:
            in_res, in_ok = self._bridge.evaluate_action(
                payload=payload,
                authority=0.6,
                sensitivity=self._in_sensitivity,
                event_type="intercepted_inbound",
                wrapped_agent=self.name,
            )
        except PermissionError:
            return Response(TextMessage("[QUARANTINE]", self.name))

        if not in_ok:
            return Response(
                TextMessage(
                    f"[INTERCEPTED/DENIED] {in_res.reason}", self.name
                )
            )

        # Delegate to inner agent
        inner_response: Response = await self._inner.on_messages(
            messages, cancellation_token
        )

        # Outbound check
        out_text = inner_response.chat_message.content
        try:
            out_res, out_ok = self._bridge.evaluate_action(
                payload=out_text,
                authority=0.7,
                sensitivity=self._out_sensitivity,
                event_type="intercepted_outbound",
                wrapped_agent=self.name,
            )
        except PermissionError:
            return Response(TextMessage("[QUARANTINE/RESPONSE]", self.name))

        if not out_ok:
            return Response(
                TextMessage(
                    f"[INTERCEPTED/RESPONSE DENIED] {out_res.reason}", self.name
                )
            )

        return inner_response

    async def on_reset(self, ct: CancellationToken) -> None:
        if hasattr(self._inner, "on_reset"):
            await self._inner.on_reset(ct)


# ─── TIER 3 — AegisGroupChatSecurity ─────────────────────────────────────────

class AegisGroupChatSecurity:
    """
    Fleet-level security validator for AutoGen multi-agent teams.

    Validates all registered agents' passports and session health before
    a group chat begins, and produces a consolidated security report
    after termination.

    Usage
    -----
    security = AegisGroupChatSecurity(adapter)
    security.register(researcher)
    security.register(writer)
    security.start()                  # validates all; raises if any expired
    # ... run your RoundRobinGroupChat ...
    report = security.shutdown_report()
    """

    def __init__(self, adapter: AegisAdapter) -> None:
        self._adapter = adapter
        self._agents: List[AegisChatAgent] = []
        self._started = False

    def register(self, agent: AegisChatAgent) -> "AegisGroupChatSecurity":
        self._agents.append(agent)
        return self

    def start(self) -> None:
        """Start all agents; fail atomically if any passport is expired."""
        errors = []
        for agent in self._agents:
            if agent._passport.is_expired():
                errors.append(
                    f"Agent {agent.name!r} passport {agent._passport.passport_id} expired"
                )

        if errors:
            _emit(LOG, "error", "AegisGroupChatSecurity", "start_failed",
                  errors=errors)
            raise PermissionError(
                "Group chat blocked — expired passport(s): " + "; ".join(errors)
            )

        for agent in self._agents:
            agent.start()

        self._started = True
        _emit(LOG, "info", "AegisGroupChatSecurity", "team_started",
              agent_count=len(self._agents),
              agents=[a.name for a in self._agents])

    def shutdown_report(self) -> Dict[str, Any]:
        """Shut down all agents and return a consolidated security report."""
        if not self._started:
            raise RuntimeError("start() must be called before shutdown_report()")

        results = {}
        for agent in self._agents:
            if agent._bridge:
                v_ok, t_ok = agent.shutdown()
                results[agent.name] = {
                    "vault_chain_ok": v_ok,
                    "tlog_chain_ok":  t_ok,
                    "vault_entries":  agent._bridge.vault.length,
                    "warp_score":     round(agent._bridge.session.warp_score, 4),
                    "session_state":  agent._bridge.session.state.value,
                }

        v_ok, t_ok = self._adapter.verify_all_chains()
        report = {
            "fleet_vault_chain_ok": v_ok,
            "fleet_tlog_chain_ok":  t_ok,
            "fleet_vault_entries":  self._adapter.vault.length,
            "fleet_tlog_entries":   self._adapter.tlog.length,
            "agents":               results,
        }
        _emit(LOG, "info", "AegisGroupChatSecurity", "shutdown_report",
              fleet_vault_ok=v_ok, fleet_tlog_ok=t_ok,
              total_vault_entries=self._adapter.vault.length)
        return report


# ─── TEST SUITE ───────────────────────────────────────────────────────────────

import pytest

POLICY_HASH = hashlib.sha256(b"autogen-policy-v1").hexdigest()

def _passport(model_id: str = "ag-agent-1", ttl: int = 3600,
              caps: frozenset = frozenset({"chat"}),
              expired: bool = False) -> SemanticPassport:
    p = SemanticPassport(
        model_id=model_id,
        version="1.0.0",
        policy_hash=POLICY_HASH,
        ttl_seconds=1 if expired else ttl,
        capabilities=caps,
    )
    if expired:
        object.__setattr__(p, "issued_at", time.time() - 10)
    return p

def _adapter() -> AegisAdapter:
    return AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
    ))

def _agent(name: str = "agent-1",
           adapter: Optional[AegisAdapter] = None,
           expired: bool = False,
           handler=None) -> AegisChatAgent:
    adp = adapter or _adapter()
    return AegisChatAgent(
        name=name,
        description="test agent",
        passport=_passport(name, expired=expired),
        adapter=adp,
        handler=handler,
        in_sensitivity=0.10,
        out_sensitivity=0.10,
    )


class TestAegisChatAgent:
    def test_start_activates_session(self):
        agent = _agent().start()
        assert agent._bridge.session.state == SessionState.ACTIVE

    def test_expired_passport_blocked(self):
        agent = _agent(expired=True)
        with pytest.raises(PermissionError, match="expired"):
            agent.start()

    def test_clean_message_allowed(self):
        agent = _agent().start()
        ct  = CancellationToken()
        msg = TextMessage("Hello, what is AI?", "user")
        response = asyncio.run(agent.on_messages([msg], ct))
        assert "[DENIED]" not in response.chat_message.content
        assert "[QUARANTINE]" not in response.chat_message.content
        assert agent._bridge.vault.length >= 1

    def test_high_sensitivity_inbound_denied(self):
        adp   = AegisAdapter(policy=PolicyEngine(sensitivity_ceiling=0.01))
        agent = AegisChatAgent(
            "sensitive-agent", "test",
            _passport(), adp,
            in_sensitivity=0.90,
        ).start()
        ct  = CancellationToken()
        msg = TextMessage("sensitive payload", "user")
        response = asyncio.run(agent.on_messages([msg], ct))
        assert "[DENIED]" in response.chat_message.content
        assert agent._bridge.vault.length == 0   # denied → not vaulted

    def test_cancelled_token_returns_cancelled(self):
        agent = _agent().start()
        ct    = CancellationToken()
        ct.cancel()
        msg  = TextMessage("any", "user")
        resp = asyncio.run(agent.on_messages([msg], ct))
        assert "[CANCELLED]" in resp.chat_message.content

    def test_quarantine_returns_notice(self):
        agent = _agent().start()
        # Drive to quarantine
        for _ in range(8):
            agent._bridge.session.record(PolicyDecision.DENY)
        ct  = CancellationToken()
        msg = TextMessage("any message", "user")
        resp = asyncio.run(agent.on_messages([msg], ct))
        assert "[QUARANTINE]" in resp.chat_message.content

    def test_on_reset_clears_history(self):
        agent = _agent().start()
        agent._message_history.append(TextMessage("x", "user"))
        asyncio.run(agent.on_reset(CancellationToken()))
        assert agent._message_history == []

    def test_custom_handler_called(self):
        async def echo_handler(msgs, ct):
            return TextMessage(f"echo:{msgs[-1].content}", "bot")

        agent = _agent(handler=echo_handler).start()
        ct    = CancellationToken()
        msg   = TextMessage("ping", "user")
        resp = asyncio.run(agent.on_messages([msg], ct))
        assert "echo:ping" in resp.chat_message.content

    def test_shutdown_chain_integrity(self):
        agent = _agent().start()
        ct    = CancellationToken()
        asyncio.run(agent.on_messages([TextMessage("hello", "user")], ct))
        v_ok, t_ok = agent.shutdown()
        assert v_ok
        assert t_ok


class TestAegisMessageInterceptor:
    def test_intercepts_and_allows_clean(self):
        class EchoAgent:
            name = "echo"; description = "echo"
            async def on_messages(self, msgs, ct):
                return Response(TextMessage(msgs[-1].content, "echo"))
            async def on_reset(self, ct): pass

        adp     = _adapter()
        bridge  = adp.register_agent(_passport(), "autogen")
        bridge.start()
        wrapper = AegisMessageInterceptor(EchoAgent(), bridge)
        msg     = TextMessage("hello world", "user")
        resp = asyncio.run(wrapper.on_messages([msg], CancellationToken()))
        assert "hello world" in resp.chat_message.content

    def test_intercepts_and_blocks_inbound(self):
        class EchoAgent:
            name = "echo"; description = ""
            async def on_messages(self, msgs, ct):
                return Response(TextMessage("ok", "echo"))

        adp    = AegisAdapter(policy=PolicyEngine(sensitivity_ceiling=0.01))
        bridge = adp.register_agent(_passport(), "autogen")
        bridge.start()
        wrapper = AegisMessageInterceptor(
            EchoAgent(), bridge, in_sensitivity=0.90
        )
        resp = asyncio.run(
            wrapper.on_messages([TextMessage("payload", "user")],
                                CancellationToken())
        )
        assert "INTERCEPTED/DENIED" in resp.chat_message.content


class TestAegisGroupChatSecurity:
    def test_valid_team_starts(self):
        adp     = _adapter()
        agents  = [_agent(f"agent-{i}", adp) for i in range(3)]
        sec     = AegisGroupChatSecurity(adp)
        for a in agents:
            sec.register(a)
        sec.start()
        assert all(a._bridge.session.state == SessionState.ACTIVE
                   for a in agents)

    def test_expired_passport_blocks_team(self):
        adp    = _adapter()
        good   = _agent("good-agent", adp)
        bad    = _agent("bad-agent",  adp, expired=True)
        sec    = AegisGroupChatSecurity(adp)
        sec.register(good).register(bad)
        with pytest.raises(PermissionError, match="expired"):
            sec.start()

    def test_shutdown_report_structure(self):
        adp = _adapter()
        a1  = _agent("r1", adp)
        a2  = _agent("r2", adp)
        sec = AegisGroupChatSecurity(adp)
        sec.register(a1).register(a2)
        sec.start()
        # Process one message each
        ct = CancellationToken()
        for agent in [a1, a2]:
            asyncio.run(agent.on_messages([TextMessage("hello", "user")], ct))
        report = sec.shutdown_report()
        assert report["fleet_vault_chain_ok"] is True
        assert report["fleet_tlog_chain_ok"]  is True
        assert "r1" in report["agents"]
        assert "r2" in report["agents"]

    def test_not_started_raises_on_report(self):
        sec = AegisGroupChatSecurity(_adapter())
        with pytest.raises(RuntimeError, match="start"):
            sec.shutdown_report()


# ─── DEMO ENTRYPOINT ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Aegis Protocol + AutoGen v0.4 AgentChat Integration Demo")
    print("=" * 70 + "\n")

    adapter = AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
    ))

    # ── define two specialised agents ────────────────────────────────────────
    async def researcher_handler(msgs, ct):
        query = msgs[-1].content
        return TextMessage(
            f"Research findings for '{query}': AI governance frameworks "
            "are evolving rapidly with new standards in 2025.",
            "researcher",
        )

    async def writer_handler(msgs, ct):
        prev = msgs[-1].content
        return TextMessage(
            f"Executive summary: {prev[:80]}...",
            "writer",
        )

    researcher = AegisChatAgent(
        name="researcher",
        description="Conducts research on given topics",
        passport=SemanticPassport(
            model_id="researcher",
            version="1.0.0",
            policy_hash=POLICY_HASH,
            ttl_seconds=3600,
            capabilities=frozenset({"read", "research"}),
        ),
        adapter=adapter,
        handler=researcher_handler,
        in_sensitivity=0.10,
        out_sensitivity=0.15,
    )

    writer = AegisChatAgent(
        name="writer",
        description="Writes summaries based on research",
        passport=SemanticPassport(
            model_id="writer",
            version="1.0.0",
            policy_hash=POLICY_HASH,
            ttl_seconds=3600,
            capabilities=frozenset({"write", "summarise"}),
        ),
        adapter=adapter,
        handler=writer_handler,
        in_sensitivity=0.10,
        out_sensitivity=0.10,
    )

    # ── fleet validation ──────────────────────────────────────────────────────
    print("Phase 1: Fleet validation")
    security = AegisGroupChatSecurity(adapter)
    security.register(researcher).register(writer)
    security.start()
    print(f"  Researcher session: {researcher._bridge.session.session_id}")
    print(f"  Writer session    : {writer._bridge.session.session_id}")

    # ── simulate a two-turn exchange ──────────────────────────────────────────
    print("\nPhase 2: Message exchange")

    async def run_demo():
        ct = CancellationToken()

        # Turn 1: user → researcher
        user_msg = TextMessage("Analyse AI safety governance standards", "user")
        r_resp   = await researcher.on_messages([user_msg], ct)
        print(f"  Researcher → {r_resp.chat_message.content[:80]}...")

        # Turn 2: researcher output → writer
        w_resp = await writer.on_messages([r_resp.chat_message], ct)
        print(f"  Writer     → {w_resp.chat_message.content[:80]}...")

        return r_resp, w_resp

    asyncio.run(run_demo())

    # ── fleet shutdown report ─────────────────────────────────────────────────
    print("\nPhase 3: Fleet shutdown report")
    report = security.shutdown_report()
    print(f"  Fleet vault chain   : {'PASS' if report['fleet_vault_chain_ok'] else 'FAIL'}")
    print(f"  Fleet tlog chain    : {'PASS' if report['fleet_tlog_chain_ok'] else 'FAIL'}")
    print(f"  Total vault entries : {report['fleet_vault_entries']}")
    for name, stats in report["agents"].items():
        print(f"  [{name}] warp={stats['warp_score']:.3f}  "
              f"state={stats['session_state']}  "
              f"vault={stats['vault_entries']}")
    print("\nDemo complete.\n")