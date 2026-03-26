"""
Aegis Protocol (Semantic Passport System)
=========================================
Copyright 2026 Gary Gray (github.com/<your-github-handle>)

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
import time
import pytest

from python.aegis_protocol.adapters.aegis_adapter import (
    SemanticPassport,
    PolicyEngine,
    SemanticScore,
    PolicyDecision,
    AuditVault,
    AegisAdapter,
    SessionGuard,
    AegisFrameworkBridge,
)


# ---------------------------------------------------------------------------
# Passport Tests
# ---------------------------------------------------------------------------

def test_passport_expiration():
    p = SemanticPassport(
        model_id="agent1",
        version="1.0",
        policy_hash="abc",
        ttl_seconds=1,
    )
    assert not p.is_expired()
    time.sleep(1.1)
    assert p.is_expired()


def test_passport_capabilities():
    p = SemanticPassport(
        model_id="agent1",
        version="1.0",
        policy_hash="abc",
        ttl_seconds=0,
        capabilities=frozenset({"read", "write"}),
    )
    assert p.has_capability("read")
    assert not p.has_capability("delete")


# ---------------------------------------------------------------------------
# Policy Engine Tests
# ---------------------------------------------------------------------------

def test_policy_allow():
    engine = PolicyEngine()
    score = SemanticScore(authority=0.8, sensitivity=0.1)
    result = engine.evaluate(score)
    assert result.decision == PolicyDecision.ALLOW


def test_policy_flag():
    engine = PolicyEngine(flag_threshold=0.2)
    score = SemanticScore(authority=0.8, sensitivity=0.25)
    result = engine.evaluate(score)
    assert result.decision == PolicyDecision.FLAG


def test_policy_deny_sensitivity():
    engine = PolicyEngine(sensitivity_ceiling=0.3)
    score = SemanticScore(authority=0.8, sensitivity=0.5)
    result = engine.evaluate(score)
    assert result.decision == PolicyDecision.DENY


def test_policy_deny_authority():
    engine = PolicyEngine(authority_floor=0.5)
    score = SemanticScore(authority=0.2, sensitivity=0.1)
    result = engine.evaluate(score)
    assert result.decision == PolicyDecision.DENY


# ---------------------------------------------------------------------------
# Audit Vault Tests
# ---------------------------------------------------------------------------

def test_audit_vault_append_and_verify():
    vault = AuditVault()
    result = PolicyEngine().evaluate(SemanticScore(0.8, 0.1))
    entry = vault.append(
        agent_id="agent1",
        session_id="sess1",
        event_type="test_event",
        payload="hello",
        result=result,
        framework="test",
    )
    assert vault.length == 1
    assert vault.verify_chain()
    assert entry.payload_hash == entry.payload_hash


# ---------------------------------------------------------------------------
# Session Guard Tests
# ---------------------------------------------------------------------------

def test_session_guard_state_transitions():
    sg = SessionGuard(agent_id="agent1")
    sg.activate()
    assert sg.state == sg.state.ACTIVE

    # Three FLAGs should NOT cross SUSPECT threshold (0.40)
    sg.record(PolicyDecision.FLAG)
    sg.record(PolicyDecision.FLAG)
    sg.record(PolicyDecision.FLAG)
    assert sg.warp_score == pytest.approx(0.36)
    assert sg.state == sg.state.ACTIVE  # correct behavior

    # Fourth FLAG crosses SUSPECT threshold
    sg.record(PolicyDecision.FLAG)
    assert sg.state == sg.state.SUSPECT

    # Force quarantine by pushing warp score above 0.70
    sg.warp_score = 0.70
    sg.record(PolicyDecision.DENY)
    assert sg.state == sg.state.QUARANTINE

    # Resync returns to ACTIVE
    sg.resync()
    assert sg.state == sg.state.ACTIVE


# ---------------------------------------------------------------------------
# Framework Bridge Tests
# ---------------------------------------------------------------------------

def test_framework_bridge_allows_action():
    passport = SemanticPassport(
        model_id="agent1",
        version="1.0",
        policy_hash="abc",
        ttl_seconds=0,
    )
    bridge = AegisFrameworkBridge(passport)
    bridge.start()
    result, allowed = bridge.evaluate_action("payload", authority=0.8, sensitivity=0.1)
    assert allowed
    assert result.decision == PolicyDecision.ALLOW


def test_framework_bridge_denies_action():
    passport = SemanticPassport(
        model_id="agent1",
        version="1.0",
        policy_hash="abc",
        ttl_seconds=0,
    )
    bridge = AegisFrameworkBridge(passport)
    bridge.start()
    result, allowed = bridge.evaluate_action("payload", authority=0.1, sensitivity=0.9)
    assert not allowed
    assert result.decision == PolicyDecision.DENY


# ---------------------------------------------------------------------------
# Adapter Registry Tests
# ---------------------------------------------------------------------------

def test_adapter_register_agent():
    adapter = AegisAdapter()
    passport = SemanticPassport(
        model_id="agent1",
        version="1.0",
        policy_hash="abc",
        ttl_seconds=0,
    )
    bridge = adapter.register_agent(passport, framework="testfw")
    assert bridge.passport.model_id == "agent1"
    assert adapter.vault.length == 0
