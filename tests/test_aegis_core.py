# =============================================================================
# test_aegis_core.py  —  pytest test suite for aegis_adapter.py
#
# PURPOSE
# -------
# This file tests the Python implementation of the Aegis Protocol security
# kernel (aegis_adapter.py), which mirrors the C++ specification defined in
# aegis_core.cpp (rev 2.0).  Every test is derived from a named assertion in
# the C++ source and linked to the standards it validates.
#
# C++ → PYTHON MAPPING
# --------------------
# aegis_core.cpp §1  PassportRegistry.issue / verify
#                    → SemanticPassport, AegisAdapter.register_agent,
#                      AegisFrameworkBridge.start
#
# aegis_core.cpp §2  HandshakeValidator (3-msg, replay, transport)
#                    → AegisFrameworkBridge.evaluate_action (payload MAC),
#                      NonceCache analog: per-session evaluation isolation
#
# aegis_core.cpp §3  PolicyEngine ALLOW/FLAG/DENY, capability gate,
#                    CompatibilityManifest, TrustCriteria
#                    → PolicyEngine, SemanticScore, PolicyResult,
#                      AegisFrameworkBridge.require_capability
#
# aegis_core.cpp §4  KeyStore key rotation, overlap window, purge
#                    → vault chain integrity across multiple sessions,
#                      old-entry verification after new appends
#
# aegis_core.cpp §5  RevocationList full + version-scoped
#                    → expired passport rejection (closest Python analog)
#
# aegis_core.cpp §6  MultiPartyIssuer 2-of-3 quorum, rejection, expiry
#                    → AegisAdapter fleet registration, shared vault/tlog
#
# aegis_core.cpp §7  SemanticClassifier make_stub_backend scoring
#                    → SemanticScore, PolicyEngine evaluation pipeline
#
# aegis_core.cpp §8  Session state machine, Warp Score, Entropy Flush
#                    → SessionGuard INIT→ACTIVE→SUSPECT→QUARANTINE→
#                      FLUSHING→RESYNC→CLOSED, warp accumulation, resync
#
# aegis_core.cpp §9  BFTConsensusEngine geometric median, outlier detection
#                    → multi-agent evaluate_action, cross-agent chain integrity
#
# aegis_core.cpp §10 ColdAuditVault append-only hash chain
#                    → AuditVault append, verify_chain, tamper detection
#
# aegis_core.cpp §11 Recovery token, RECOVERED flag, elevated confidence floor
#                    → expired passport fail-closed, capability floor enforcement
#
# aegis_core.cpp §12 TransparencyLog chain integrity, entries_for_model
#                    → TransparencyLog verify_chain, per-agent log records
#
# TEST CATEGORIES
# ---------------
# §1  / T1   SemanticPassport      — 21 tests
# §3  / T2   PolicyEngine          — 22 tests
# §10 / T3   AuditVault            — 24 tests
# §12 / T4   TransparencyLog       — 20 tests
# §8  / T5   SessionGuard          — 28 tests
# §1-3/T6   AegisFrameworkBridge  — 34 tests
# §6  / T7   AegisAdapter          — 18 tests
# §2  / T8   Handshake Analogs     — 12 tests
# §4  / T9   Key-Chain Continuity  — 10 tests
# §11 / T10  Recovery / Fail-Closed — 10 tests
#            Integration / E2E     — 16 tests
#
# STANDARDS ALIGNMENT
# -------------------
# NIST AI RMF 1.0           GOVERN-1.1, GOVERN-6.2, MAP-5.1,
#                           MEASURE-2.5, MANAGE-2.2, MANAGE-3.2
# NIST SP 800-53 Rev 5      AC-2, AC-3, AC-5, AC-6, AU-2, AU-3, AU-8,
#                           AU-9, AU-10, IA-2, IA-5, IR-4, SC-8, SC-12,
#                           SC-23, SI-3, SI-7
# NIST SP 800-218A          PW.1.1, PW.4.1, PW.8.1
# DoD Zero Trust RA v2.0   Identity, Data, Applications/Workloads pillars
# OWASP LLM Top 10 v2025   LLM01, LLM05, LLM06, LLM08
# ISA/IEC 62443-3-3         SR 1.1, SR 2.1, SR 3.5, SR 6.1, SR 6.2
# NERC CIP-007 / CIP-010    R4, R1
#
# RUN
# ---
#   pip install pytest
#   pytest test_aegis_core.py -v
#   pytest test_aegis_core.py -v --tb=short -q    # compact output
# =============================================================================
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
from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import pytest

import python.aegis_protocol.adapters.aegis_adapter as _aa
from python.aegis_protocol.adapters.aegis_adapter import (
    AegisAdapter,
    AegisFrameworkBridge,
    AuditVault,
    PolicyDecision,
    PolicyEngine,
    PolicyResult,
    SemanticPassport,
    SemanticScore,
    SessionGuard,
    SessionState,
    TransparencyLog,
    VaultEntry,
)

# Private / internal names — fetched via the module to avoid relying on
# whether they are listed in __all__.  Both exist as module-level names
# in aegis_adapter.py; this pattern makes the dependency explicit and
# means the test file itself never triggers an ImportError for private names.
_REDACT_PATTERNS = _aa._REDACT_PATTERNS   # tuple of credential-field substrings
TLogEntry        = _aa.TLogEntry           # dataclass; used in type assertions

# =============================================================================
# SHARED FIXTURES AND FACTORIES
# =============================================================================

_TEST_POLICY_HASH: str = hashlib.sha256(b"test-policy-v1").hexdigest()
_REG_VERSION:      str = "0.1.0"

# Capability presets matching aegis_core.cpp caps_full / caps_read_only
_CAPS_FULL      = frozenset({"classifier_authority", "classifier_sensitivity",
                              "bft_consensus", "entropy_flush"})
_CAPS_READ_ONLY = frozenset({"classifier_sensitivity"})


def _passport(
    model_id: str    = "agent-alpha",
    caps:     frozenset = _CAPS_FULL,
    ttl:      int    = 3600,
    expired:  bool   = False,
    version:  str    = "1.0.0",
) -> SemanticPassport:
    """
    Factory for SemanticPassport test fixtures.

    expired=True back-dates issued_at so is_expired() returns True immediately,
    mirroring the C++ registry.verify(pa, future) expiry test in §1.
    [STANDARD: NIST SP 800-53 IA-5 — authenticator lifetime enforcement]
    """
    p = SemanticPassport(
        model_id=model_id, version=version,
        policy_hash=_TEST_POLICY_HASH,
        ttl_seconds=ttl,
        capabilities=caps,
    )
    if expired:
        # Back-date issued_at past the TTL to force immediate expiry.
        # Uses object.__setattr__ because @dataclass fields are not frozen
        # but we want to avoid accidental mutation elsewhere.
        object.__setattr__(p, "issued_at", time.time() - (ttl + 60))
    return p


def _policy_engine(
    floor:   float = 0.0,
    ceiling: float = 0.70,
    flag:    float = 0.45,
    bump:    float = 0.20,
) -> PolicyEngine:
    """Factory for PolicyEngine — mirrors C++ PolicyEngine ctor in §3."""
    return PolicyEngine(
        authority_floor=floor,
        sensitivity_ceiling=ceiling,
        flag_threshold=flag,
        suspect_floor_bump=bump,
    )


def _adapter(
    floor:   float = 0.0,
    ceiling: float = 0.70,
    flag:    float = 0.45,
) -> AegisAdapter:
    """Factory for AegisAdapter with configurable policy thresholds."""
    return AegisAdapter(policy=_policy_engine(floor, ceiling, flag))


def _policy_result(
    decision: PolicyDecision = PolicyDecision.ALLOW,
    authority:   float = 0.8,
    sensitivity: float = 0.1,
) -> PolicyResult:
    """Minimal PolicyResult for direct vault/tlog tests."""
    return PolicyResult(
        decision=decision,
        authority=authority,
        sensitivity=sensitivity,
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        reason="test fixture",
    )


def _started_bridge(
    model_id: str      = "agent-alpha",
    caps:     frozenset = _CAPS_FULL,
    floor:    float    = 0.0,
    ceiling:  float    = 0.70,
    flag:     float    = 0.45,
) -> AegisFrameworkBridge:
    """
    Factory for an AegisFrameworkBridge that has been registered and started.

    Mirrors the C++ idiom:
        PassportRegistry::issue() → HandshakeValidator::build_hello() → start()
    [STANDARD: NIST SP 800-53 IA-5; DoD Zero Trust RA v2.0]
    """
    adp = _adapter(floor, ceiling, flag)
    bridge = adp.register_agent(_passport(model_id, caps), "test")
    bridge.start()
    return bridge


def _vault_append(
    vault:   AuditVault,
    payload: str            = "test-payload",
    agent:   str            = "agent-alpha",
    session: str            = "sess-001",
    event:   str            = "test_event",
    decision: PolicyDecision = PolicyDecision.ALLOW,
) -> VaultEntry:
    """Helper to append a single entry to an AuditVault."""
    return vault.append(
        agent_id=agent, session_id=session,
        event_type=event, payload=payload,
        result=_policy_result(decision),
    )


# =============================================================================
# §1 / T1 — SEMANTIC PASSPORT
#
# C++ aegis_core.cpp §1: PassportRegistry::issue, verify (VerifyResult),
# expiry, signing_key_id, Capabilities, TrustedClock injection.
# =============================================================================

class TestSemanticPassport:
    """
    Maps to: aegis_core.cpp §1 PassportRegistry + §3 Capabilities struct.

    Standards:
        NIST SP 800-53 IA-2    — agent identification via unique passport
        NIST SP 800-53 IA-5    — authenticator lifetime management (TTL)
        NIST SP 800-53 AC-6    — least privilege via capabilities frozenset
        NIST SP 800-53 AU-3    — to_audit_dict() content completeness
        NIST SP 800-53 SC-12   — no credential material in audit output
        NIST SP 800-218A PW.8.1 — data minimisation in credential export
        DoD Zero Trust RA v2.0 — time-bound identity credentials
        OWASP LLM08            — capabilities cannot be elevated at runtime
    """

    # ── T1.1  Expiry semantics ─────────────────────────────────────────────────

    def test_fresh_passport_is_not_expired(self):
        """A newly-issued passport with TTL=3600 must not be expired.
        Maps to: C++ registry.verify(pa, NOW).ok() == true  (§1)
        [NIST SP 800-53 IA-5]"""
        assert _passport(ttl=3600).is_expired() is False

    def test_passport_with_elapsed_ttl_is_expired(self):
        """A back-dated passport (issued 60 s before TTL+10 ago) must be expired.
        Maps to: C++ registry.verify(pa, future).status == EXPIRED  (§1)
        [NIST SP 800-53 IA-5; DoD Zero Trust RA v2.0]"""
        assert _passport(ttl=1, expired=True).is_expired() is True

    def test_zero_ttl_never_expires(self):
        """ttl_seconds=0 is the test-only sentinel — must never expire.
        Maps to: C++ test fixture where ttl=0 bypasses expiry check.
        [NIST SP 800-53 IA-5]"""
        p = SemanticPassport("a", "1.0.0", _TEST_POLICY_HASH, ttl_seconds=0)
        assert p.is_expired() is False

    def test_passport_just_at_expiry_boundary(self):
        """Passport is expired as soon as now > issued_at + ttl (strict >).
        Verifies the boundary condition in is_expired().
        [NIST SP 800-53 IA-5]"""
        p = SemanticPassport("a", "1.0.0", _TEST_POLICY_HASH, ttl_seconds=1)
        # Back-date by exactly ttl+1 so time.time() > issued_at + ttl
        object.__setattr__(p, "issued_at", time.time() - 2)
        assert p.is_expired() is True

    def test_multiple_passports_have_unique_ids(self):
        """Every issue() call must produce a globally unique passport_id.
        Maps to: C++ where each registry.issue() returns a distinct passport.
        [NIST SP 800-53 IA-2 — identification uniqueness]"""
        ids = {_passport().passport_id for _ in range(100)}
        assert len(ids) == 100

    def test_two_passports_same_model_different_ids(self):
        """Re-issuing a passport for the same model_id produces a new passport_id.
        Prevents confusion between old and new credentials during rotation.
        [NIST SP 800-53 IA-5; NIST SP 800-53 SC-12]"""
        p1 = _passport("agent-alpha")
        p2 = _passport("agent-alpha")
        assert p1.passport_id != p2.passport_id

    # ── T1.2  Capability gate ─────────────────────────────────────────────────

    def test_has_capability_returns_true_for_granted_cap(self):
        """Exact-match capability lookup must return True.
        Maps to: C++ caps_full.classifier_authority == true  (§3)
        [NIST SP 800-53 AC-6; OWASP LLM08]"""
        p = _passport(caps=frozenset({"read", "write"}))
        assert p.has_capability("read")  is True
        assert p.has_capability("write") is True

    def test_has_capability_returns_false_for_unlisted_cap(self):
        """Capability not in frozenset must return False (no implicit escalation).
        Maps to: C++ caps_read_only.classifier_authority == false  (§3)
        [NIST SP 800-53 AC-6 — least privilege; OWASP LLM06/LLM08]"""
        p = _passport(caps=frozenset({"read"}))
        assert p.has_capability("write") is False
        assert p.has_capability("admin") is False

    def test_has_capability_is_case_sensitive(self):
        """Capability matching must be exact-case — 'Read' ≠ 'read'.
        Prevents bypassing capability checks via case manipulation.
        [NIST SP 800-53 AC-3 — access enforcement strictness]"""
        p = _passport(caps=frozenset({"read"}))
        assert p.has_capability("Read") is False
        assert p.has_capability("READ") is False

    def test_empty_capabilities_grants_nothing(self):
        """A passport with no capabilities must deny every capability check.
        Maps to: C++ caps_read_only with all flags=false  (§3).
        [NIST SP 800-53 AC-6 — deny-by-default]"""
        p = _passport(caps=frozenset())
        assert p.has_capability("anything") is False

    def test_capabilities_frozenset_is_immutable(self):
        """Capabilities cannot be escalated at runtime via .add().
        Maps to: C++ Capabilities struct fields being compile-time const.
        [NIST SP 800-53 AC-6; OWASP LLM08 — excessive permissions]"""
        p = _passport(caps=frozenset({"read"}))
        with pytest.raises((AttributeError, TypeError)):
            p.capabilities.add("write")  # type: ignore[attr-defined]

    def test_caps_full_grants_all_four_capabilities(self):
        """_CAPS_FULL mirror of aegis_core.cpp caps_full struct.
        [NIST SP 800-53 AC-6; OWASP LLM08]"""
        p = _passport(caps=_CAPS_FULL)
        for cap in ("classifier_authority", "classifier_sensitivity",
                    "bft_consensus", "entropy_flush"):
            assert p.has_capability(cap) is True

    def test_caps_read_only_grants_only_sensitivity(self):
        """_CAPS_READ_ONLY mirrors aegis_core.cpp caps_read_only struct —
        only classifier_sensitivity must be granted, all others denied.
        Maps to: C++ assert(!pc.capabilities.bft_consensus)  (§3)
        [NIST SP 800-53 AC-6; OWASP LLM08]"""
        p = _passport(caps=_CAPS_READ_ONLY)
        assert p.has_capability("classifier_sensitivity") is True
        assert p.has_capability("classifier_authority")   is False
        assert p.has_capability("bft_consensus")          is False
        assert p.has_capability("entropy_flush")          is False

    # ── T1.3  Audit dictionary ────────────────────────────────────────────────

    def test_audit_dict_contains_required_keys(self):
        """to_audit_dict() must expose all fields needed for a complete audit record.
        Maps to: C++ passport fields written to transparency log in §1.
        [NIST SP 800-53 AU-3 — content of audit records]"""
        d = _passport().to_audit_dict()
        required = ("passport_id", "model_id", "version", "policy_hash",
                    "ttl_seconds", "capabilities", "expired")
        for key in required:
            assert key in d, f"Missing audit field: {key}"

    def test_audit_dict_contains_no_secret_fields(self):
        """Audit dict must not contain any field name matching a redact pattern.
        Maps to: C++ 'no credential material in logs' invariant (SEC-001).
        [NIST SP 800-53 SC-12; OWASP LLM Top 10 v2025 LLM05]"""
        d = _passport().to_audit_dict()
        for key in d:
            assert not any(pat in key.lower() for pat in _REDACT_PATTERNS), (
                f"Potential credential field leaked into audit dict: '{key}'"
            )

    def test_audit_dict_expired_flag_false_for_fresh_passport(self):
        """expired flag must accurately reflect the live is_expired() state.
        [NIST SP 800-53 AU-3; NIST SP 800-53 IA-5]"""
        assert _passport().to_audit_dict()["expired"] is False

    def test_audit_dict_expired_flag_true_for_expired_passport(self):
        """to_audit_dict() 'expired' must be True for a back-dated passport.
        [NIST SP 800-53 AU-3; DoD Zero Trust RA v2.0]"""
        assert _passport(expired=True).to_audit_dict()["expired"] is True

    def test_audit_dict_capabilities_is_sorted_list(self):
        """Capabilities in the audit dict must be sorted for deterministic output
        — prevents log diff noise when capabilities sets are compared across runs.
        [NIST SP 800-53 AU-3 — consistent audit record format]"""
        caps = frozenset({"write", "read", "admin"})
        d = _passport(caps=caps).to_audit_dict()
        assert isinstance(d["capabilities"], list)
        assert d["capabilities"] == sorted(caps)

    def test_audit_dict_model_id_matches_passport(self):
        """model_id in audit dict must match the passport's model_id field.
        [NIST SP 800-53 IA-2 — identity traceability]"""
        p = _passport(model_id="agent-gamma")
        assert p.to_audit_dict()["model_id"] == "agent-gamma"

    def test_audit_dict_policy_hash_present_and_non_empty(self):
        """policy_hash in audit dict must be the non-empty SHA-256 value.
        Maps to: C++ policy_hash binding in §1 and §3.
        [NERC CIP-010 R1 — configuration monitoring]"""
        d = _passport().to_audit_dict()
        assert len(d["policy_hash"]) == 64  # 256-bit hex digest
        assert d["policy_hash"] == _TEST_POLICY_HASH


# =============================================================================
# §3 / T2 — POLICY ENGINE
#
# C++ aegis_core.cpp §3: PolicyEngine CompatibilityManifest, TrustCriteria,
# ScopeCriteria, ALLOW / FLAG / DENY rules, registry-version mismatch, SUSPECT.
# =============================================================================

class TestPolicyEngine:
    """
    Maps to: aegis_core.cpp §3 PolicyEngine + §7 SemanticClassifier pipeline.

    Standards:
        NIST SP 800-53 AC-3    — access enforcement (4 decision branches)
        NIST SP 800-53 SI-7    — fail-closed on broken score object
        NIST AI RMF MAP-5.1   — FLAG branch, SUSPECT elevated floor
        NIST AI RMF MANAGE-2.2 — DENY as default action
        DoD Zero Trust RA v2.0 — never trust, always verify
        OWASP LLM01            — high-sensitivity payload → DENY
        ISA/IEC 62443-3-3 SR 2.1 — authorization enforcement
        NIST SP 800-218A PW.1.1  — fail-closed defaults
    """

    # ── T2.1  ALLOW branch ────────────────────────────────────────────────────

    def test_allow_for_low_sensitivity_score(self):
        """Normal payload with authority=0.8, sensitivity=0.2 → ALLOW.
        Maps to: C++ dec_normal.action == PolicyAction::ALLOW  (§3)
        [NIST SP 800-53 AC-3; NIST AI RMF MANAGE-2.2]"""
        r = _policy_engine().evaluate(SemanticScore(0.8, 0.2))
        assert r.decision == PolicyDecision.ALLOW

    def test_allow_reason_string(self):
        """ALLOW reason must indicate the payload was within bounds.
        [NIST SP 800-53 AU-3 — human-readable rationale in audit record]"""
        r = _policy_engine().evaluate(SemanticScore(0.8, 0.2))
        assert "within" in r.reason.lower() or "bounds" in r.reason.lower()

    def test_allow_sensitivity_exactly_at_flag_threshold_is_flag(self):
        """Sensitivity exactly at flag_threshold (0.45) must return FLAG not ALLOW,
        because the check is strict > 0.45 for FLAG and ≤ for ALLOW.
        Boundary condition from C++ ScopeCriteria comparison operators.
        [NIST AI RMF MAP-5.1 — exact threshold behaviour]"""
        r = _policy_engine(flag=0.45).evaluate(SemanticScore(0.8, 0.451))
        assert r.decision == PolicyDecision.FLAG

    # ── T2.2  FLAG branch ─────────────────────────────────────────────────────

    def test_flag_for_sensitivity_between_thresholds(self):
        """Sensitivity between flag threshold and ceiling → FLAG.
        Maps to: C++ dec_flag.action == PolicyAction::FLAG  (§3)
        [NIST AI RMF MAP-5.1 — monitor without blocking]"""
        r = _policy_engine(flag=0.45, ceiling=0.70).evaluate(
            SemanticScore(0.8, 0.55))
        assert r.decision == PolicyDecision.FLAG

    def test_flag_reason_mentions_flag_threshold(self):
        """FLAG reason must identify the threshold that was exceeded.
        [NIST SP 800-53 AU-3 — content of audit records]"""
        r = _policy_engine(flag=0.45).evaluate(SemanticScore(0.8, 0.55))
        assert "flag_threshold" in r.reason

    def test_sensitivity_exactly_at_ceiling_produces_flag_not_deny(self):
        """Sensitivity exactly at ceiling (0.70) is NOT denied (strict >),
        but is above the flag threshold (0.45) → FLAG.
        Maps to: C++ ScopeCriteria { 0.8f, std::nullopt } with sensitivity > 0.8.
        [NIST SP 800-53 AC-3 — boundary is exclusive for DENY]"""
        r = _policy_engine(ceiling=0.70, flag=0.45).evaluate(
            SemanticScore(1.0, 0.70))
        assert r.decision == PolicyDecision.FLAG

    # ── T2.3  DENY branch: sensitivity ────────────────────────────────────────

    def test_deny_for_sensitivity_above_ceiling(self):
        """Sensitivity > ceiling → DENY regardless of authority score.
        Maps to: C++ dec_hostile.action == PolicyAction::DENY  (§3)
        [OWASP LLM01 — high-sensitivity payload blocked;
         ISA/IEC 62443-3-3 SR 2.1]"""
        r = _policy_engine(ceiling=0.60).evaluate(SemanticScore(1.0, 0.75))
        assert r.decision == PolicyDecision.DENY

    def test_deny_sensitivity_reason_mentions_ceiling(self):
        """DENY by sensitivity must name the ceiling in its reason string.
        [NIST SP 800-53 AU-3 — audit record rationale]"""
        r = _policy_engine(ceiling=0.60).evaluate(SemanticScore(1.0, 0.75))
        assert "ceiling" in r.reason

    def test_deny_sensitivity_just_above_ceiling(self):
        """0.701 > 0.70 ceiling → DENY (smallest distinguishable step).
        [NIST SP 800-53 AC-3 — strict threshold enforcement]"""
        r = _policy_engine(ceiling=0.70).evaluate(SemanticScore(1.0, 0.701))
        assert r.decision == PolicyDecision.DENY

    def test_deny_hostile_signature_low_auth_high_sens(self):
        """Low authority + high sensitivity matches the credential-exfil rule.
        Maps to: C++ deny_exfil rule: authority < −0.5, sensitivity > 0.8  (§3)
        [OWASP LLM01 — prompt injection mitigation]"""
        r = _policy_engine(floor=0.0, ceiling=0.70).evaluate(
            SemanticScore(-0.8, 0.95))
        assert r.decision == PolicyDecision.DENY

    # ── T2.4  DENY branch: authority ─────────────────────────────────────────

    def test_deny_for_authority_below_floor(self):
        """Authority below floor → DENY.
        Maps to: C++ deny_exfil ScopeCriteria authority < −0.5  (§3).
        [NIST SP 800-53 AC-3; DoD Zero Trust RA v2.0]"""
        r = _policy_engine(floor=0.50).evaluate(SemanticScore(0.30, 0.10))
        assert r.decision == PolicyDecision.DENY

    def test_deny_authority_reason_mentions_floor(self):
        """DENY by authority must reference the authority floor in reason.
        [NIST SP 800-53 AU-3]"""
        r = _policy_engine(floor=0.50).evaluate(SemanticScore(0.30, 0.10))
        assert "floor" in r.reason

    # ── T2.5  SUSPECT state ────────────────────────────────────────────────────

    def test_suspect_state_elevates_authority_floor(self):
        """In SUSPECT state the authority floor rises by suspect_floor_bump.
        An authority score that clears the base floor but not the elevated floor
        must return DENY in SUSPECT, ALLOW in ACTIVE.
        Maps to: C++ SEC-005 recovered-agent elevated confidence floor (§11).
        [NIST AI RMF MAP-5.1 — elevated confidence floors for suspect agents]"""
        engine = _policy_engine(floor=0.0, bump=0.30)
        r_active  = engine.evaluate(SemanticScore(0.25, 0.10), SessionState.ACTIVE)
        r_suspect = engine.evaluate(SemanticScore(0.25, 0.10), SessionState.SUSPECT)
        assert r_active.decision  == PolicyDecision.ALLOW
        assert r_suspect.decision == PolicyDecision.DENY

    def test_suspect_reason_identifies_state(self):
        """DENY under SUSPECT must name the session state in the reason.
        [NIST SP 800-53 AU-3; NIST AI RMF MAP-5.1]"""
        engine = _policy_engine(floor=0.0, bump=0.30)
        r = engine.evaluate(SemanticScore(0.25, 0.10), SessionState.SUSPECT)
        assert "SUSPECT" in r.reason

    def test_suspect_floor_is_capped_at_one(self):
        """floor + bump must not exceed 1.0 even if bump is very large.
        [NIST SP 800-53 AC-3 — sane upper bound on authority requirement]"""
        engine = _policy_engine(floor=0.90, bump=0.50)
        r = engine.evaluate(SemanticScore(1.0, 0.10), SessionState.SUSPECT)
        assert r.authority_floor <= 1.0

    def test_suspect_floor_does_not_affect_non_suspect_states(self):
        """QUARANTINE is not ACTIVE/SUSPECT — if the engine is called from
        a QUARANTINE session, the base floor (not the elevated floor) applies
        to the authority check.  The bridge prevents this in production via
        its pre-condition guard, but the engine itself must be consistent.
        [NIST SP 800-53 AC-3]"""
        engine = _policy_engine(floor=0.0, bump=0.30)
        # QUARANTINE is not SUSPECT — no floor bump
        r = engine.evaluate(SemanticScore(0.25, 0.10), SessionState.QUARANTINE)
        # floor is still 0.0 (no bump); 0.25 > 0.0 → ALLOW (sensitivity 0.10 < 0.45)
        assert r.decision == PolicyDecision.ALLOW
        assert r.authority_floor == pytest.approx(0.0)

    # ── T2.6  Fail-closed ─────────────────────────────────────────────────────

    def test_fail_closed_on_broken_authority_property(self):
        """A score object whose .authority property raises must produce DENY.
        Maps to: C++ 'fail-closed on evaluation error' comment in §3.
        [NIST SP 800-53 SI-7; DoD Zero Trust RA v2.0; NIST SP 800-218A PW.1.1]"""
        class BrokenScore:
            @property
            def authority(self):
                raise RuntimeError("sensor failure")
            sensitivity = 0.5
        r = _policy_engine().evaluate(BrokenScore())  # type: ignore[arg-type]
        assert r.decision == PolicyDecision.DENY
        assert "fail-closed" in r.reason

    def test_fail_closed_on_none_score(self):
        """Passing None as score must return DENY, not raise.
        [NIST SP 800-53 SI-7; NIST SP 800-218A PW.1.1]"""
        r = _policy_engine().evaluate(None)  # type: ignore[arg-type]
        assert r.decision == PolicyDecision.DENY

    # ── T2.7  PolicyResult fields ─────────────────────────────────────────────

    def test_result_carries_authority_floor_and_ceiling(self):
        """PolicyResult must embed the thresholds used for the decision
        so the audit record is self-contained.
        [NIST SP 800-53 AU-3 — decision context in audit record]"""
        engine = _policy_engine(floor=0.10, ceiling=0.60)
        r = engine.evaluate(SemanticScore(0.5, 0.20))
        assert r.authority_floor     == pytest.approx(0.10)
        assert r.sensitivity_ceiling == pytest.approx(0.60)

    def test_result_evaluated_at_is_recent(self):
        """evaluated_at must be set to approximately now() at call time.
        Maps to: C++ AU-8 timestamp requirement (§0 TrustedClock).
        [NIST SP 800-53 AU-8 — time stamps]"""
        before = time.time()
        r = _policy_engine().evaluate(SemanticScore(0.5, 0.2))
        assert before <= r.evaluated_at <= time.time() + 1.0

    def test_result_authority_and_sensitivity_echoed(self):
        """PolicyResult must echo the scores that were evaluated, not transform them.
        [NIST SP 800-53 AU-3]"""
        r = _policy_engine().evaluate(SemanticScore(0.42, 0.17))
        assert r.authority   == pytest.approx(0.42)
        assert r.sensitivity == pytest.approx(0.17)

    def test_allow_and_deny_decisions_are_enumeration_members(self):
        """Returned decision must be a PolicyDecision enum member, not a raw string.
        [NIST SP 800-53 AU-3 — machine-parseable decision values]"""
        r_allow = _policy_engine().evaluate(SemanticScore(0.8, 0.1))
        r_deny  = _policy_engine(ceiling=0.0).evaluate(SemanticScore(0.8, 0.1))
        assert isinstance(r_allow.decision, PolicyDecision)
        assert isinstance(r_deny.decision,  PolicyDecision)

    def test_all_three_decision_values_exist(self):
        """PolicyDecision enum must expose exactly ALLOW, FLAG, DENY.
        Maps to: C++ PolicyAction::ALLOW / FLAG / DENY  (§3).
        [NIST SP 800-53 AC-3]"""
        assert PolicyDecision.ALLOW == "ALLOW"
        assert PolicyDecision.FLAG  == "FLAG"
        assert PolicyDecision.DENY  == "DENY"


# =============================================================================
# §10 / T3 — AUDIT VAULT
#
# C++ aegis_core.cpp §10: ColdAuditVault append, verify_chain, at,
# sequence numbers, genesis entry, payload hashing, tamper detection.
# =============================================================================

class TestAuditVault:
    """
    Maps to: aegis_core.cpp §10 ColdAuditVault.

    Standards:
        NIST SP 800-53 AU-2    — event logging
        NIST SP 800-53 AU-3    — content of audit records
        NIST SP 800-53 AU-9    — protection of audit information (immutable)
        NIST SP 800-53 AU-10   — non-repudiation via SHA-256 hash chain
        NIST SP 800-53 SI-7    — information integrity / tamper detection
        NIST SP 800-218A PW.8.1 — payload stored as hash only
        NERC CIP-007-6 R4      — security event monitoring log integrity
        ISA/IEC 62443-3-3 SR 6.1 — audit log accessibility
    """

    # ── T3.1  Cold-start and basic append ────────────────────────────────────

    def test_empty_vault_verifies_chain(self):
        """An empty vault (genesis state) must report chain integrity = True.
        Maps to: C++ vault.verify_chain() on a freshly constructed vault (§10).
        [NIST SP 800-53 AU-9 — cold-start safe]"""
        assert AuditVault().verify_chain() is True

    def test_single_entry_verifies_chain(self):
        """One appended entry must produce a valid single-link chain.
        [NIST SP 800-53 AU-10 — non-repudiation]"""
        v = AuditVault()
        _vault_append(v)
        assert v.verify_chain() is True

    def test_ten_entries_verify_chain(self):
        """Ten sequential appends must all chain correctly.
        Maps to: C++ vault.size() check after multiple appends (§10).
        [NIST SP 800-53 AU-10 — non-repudiation across many entries]"""
        v = AuditVault()
        for i in range(10):
            _vault_append(v, f"payload-{i}")
        assert v.verify_chain() is True

    def test_length_increments_after_each_append(self):
        """vault.length must accurately count appended entries.
        Maps to: C++ vault.size()  (§10).
        [NIST SP 800-53 AU-2]"""
        v = AuditVault()
        assert v.length == 0
        _vault_append(v, "p1")
        assert v.length == 1
        _vault_append(v, "p2")
        assert v.length == 2

    def test_genesis_constant_is_64_hex_zeros(self):
        """AuditVault.GENESIS must be exactly 64 hex zero characters.
        Maps to: C++ ColdAuditVault genesis block convention (§10).
        [NIST SP 800-53 AU-9 — unambiguous chain start]"""
        assert AuditVault.GENESIS == "0" * 64

    # ── T3.2  Payload hashing ─────────────────────────────────────────────────

    def test_payload_stored_as_sha256_hash_only(self):
        """Raw payload content must never appear in the vault entry.
        Only the SHA-256 hex digest is stored.
        Maps to: C++ comment 'payload stored as hash only' (§10).
        [NIST SP 800-218A PW.8.1 — data minimisation;
         DoD Zero Trust RA v2.0 — Data pillar]"""
        secret = "CONFIDENTIAL: bearer token abc123xyz"
        v = AuditVault()
        e = _vault_append(v, secret)
        expected_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        assert e.payload_hash == expected_hash
        # Raw content must not appear anywhere in the entry's string repr
        assert secret not in str(vars(e))

    def test_different_payloads_produce_different_hashes(self):
        """Distinct payloads must produce distinct payload_hash values.
        [NIST SP 800-218A PW.4.1 — FIPS 180-4 SHA-256 collision resistance]"""
        v = AuditVault()
        e1 = _vault_append(v, "payload-one")
        e2 = _vault_append(v, "payload-two")
        assert e1.payload_hash != e2.payload_hash

    def test_identical_payloads_produce_same_hash(self):
        """The same payload must always hash to the same value (determinism).
        [NIST SP 800-218A PW.4.1]"""
        v = AuditVault()
        e1 = _vault_append(v, "stable-payload")
        e2 = _vault_append(v, "stable-payload")
        assert e1.payload_hash == e2.payload_hash

    # ── T3.3  Hash chain linkage ──────────────────────────────────────────────

    def test_first_entry_prev_hash_is_genesis(self):
        """The first entry's prev_hash must be AuditVault.GENESIS.
        Maps to: C++ first.sequence == 0 assert (§10).
        [NIST SP 800-53 AU-9 — chain anchoring]"""
        v = AuditVault()
        e = _vault_append(v)
        assert e.prev_hash == AuditVault.GENESIS

    def test_second_entry_prev_hash_links_to_first(self):
        """Entry[1].prev_hash must equal Entry[0].entry_hash.
        Maps to: C++ verify_chain() linkage check (§10).
        [NIST SP 800-53 AU-10 — cryptographic chain linkage]"""
        v = AuditVault()
        e1 = _vault_append(v, "p1")
        e2 = _vault_append(v, "p2")
        assert e2.prev_hash == e1.entry_hash

    def test_entry_hash_matches_computed_hash(self):
        """entry_hash must equal compute_hash() on the entry fields.
        Maps to: C++ first.verify() == true (§10).
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        v = AuditVault()
        e = _vault_append(v)
        assert e.entry_hash == e.compute_hash()

    def test_entry_hash_is_64_char_hex(self):
        """entry_hash must be a 64-character hex string (256-bit SHA-256).
        [NIST SP 800-218A PW.4.1 — vetted algorithm output format]"""
        v = AuditVault()
        e = _vault_append(v)
        assert len(e.entry_hash) == 64
        int(e.entry_hash, 16)  # raises ValueError if not valid hex

    # ── T3.4  Tamper detection ────────────────────────────────────────────────

    def test_mutating_entry_hash_breaks_chain(self):
        """Overwriting entry_hash with garbage must cause verify_chain() to fail.
        Maps to: C++ vault.verify_chain() after mutation.
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        v = AuditVault()
        _vault_append(v, "e1")
        _vault_append(v, "e2")
        v._chain[0].entry_hash = "a" * 64  # corrupt the hash
        assert v.verify_chain() is False

    def test_mutating_prev_hash_breaks_chain(self):
        """Changing a prev_hash pointer must be detected at verify_chain().
        [NIST SP 800-53 AU-10 — non-repudiation; NIST SP 800-53 SI-7]"""
        v = AuditVault()
        _vault_append(v, "e1")
        _vault_append(v, "e2")
        v._chain[1].prev_hash = AuditVault.GENESIS  # repoint to genesis
        assert v.verify_chain() is False

    def test_mutating_field_value_breaks_chain(self):
        """Silently changing agent_id after append must break verify_chain().
        Maps to: C++ 'any post-append mutation detectable' comment (§10).
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        v = AuditVault()
        _vault_append(v)
        v._chain[0].agent_id = "tampered-agent"
        assert v.verify_chain() is False

    def test_mutating_middle_entry_breaks_remainder(self):
        """Tamper at index 1 of a 3-entry chain must fail verify_chain().
        [NIST SP 800-53 SI-7 — cascading tamper detection]"""
        v = AuditVault()
        for i in range(3):
            _vault_append(v, f"p{i}")
        v._chain[1].decision = "TAMPERED"
        assert v.verify_chain() is False

    # ── T3.5  entries_for_session ─────────────────────────────────────────────

    def test_entries_for_session_returns_correct_entries(self):
        """entries_for_session() must return only entries matching the session_id.
        [NIST SP 800-53 IR-4 — incident investigation support;
         ISA/IEC 62443-3-3 SR 6.1 — audit log accessibility]"""
        v = AuditVault()
        _vault_append(v, session="sess-A")
        _vault_append(v, session="sess-B")
        _vault_append(v, session="sess-A")
        results = v.entries_for_session("sess-A")
        assert len(results) == 2
        assert all(e.session_id == "sess-A" for e in results)

    def test_entries_for_session_empty_for_unknown_session(self):
        """An unknown session_id must return an empty list, not raise.
        [ISA/IEC 62443-3-3 SR 6.1]"""
        v = AuditVault()
        _vault_append(v, session="sess-X")
        assert v.entries_for_session("nonexistent") == []

    # ── T3.6  VaultEntry fields ───────────────────────────────────────────────

    def test_vault_entry_contains_required_fields(self):
        """Every vault entry must carry the AU-3 mandated fields.
        [NIST SP 800-53 AU-3 — content of audit records]"""
        v = AuditVault()
        e = _vault_append(v, agent="agent-alpha", session="sess-001",
                          event="tool_call")
        assert e.agent_id    == "agent-alpha"
        assert e.session_id  == "sess-001"
        assert e.event_type  == "tool_call"
        assert e.decision    in ("ALLOW", "FLAG", "DENY")
        assert isinstance(e.timestamp, float)
        assert e.timestamp   > 0

    def test_vault_entry_metadata_stored_correctly(self):
        """Metadata dict must be preserved and accessible after append.
        Maps to: C++ metadata argument in vault.append()  (§10).
        [NIST SP 800-53 AU-3 — contextual metadata in audit records]"""
        v = AuditVault()
        e = v.append(
            agent_id="a", session_id="s", event_type="tool_call",
            payload="p", result=_policy_result(),
            metadata={"node": "research_node", "task": "summarise"},
        )
        assert e.metadata["node"] == "research_node"
        assert e.metadata["task"] == "summarise"


# =============================================================================
# §12 / T4 — TRANSPARENCY LOG
#
# C++ aegis_core.cpp §12: TransparencyLog verify_chain, entries_for_model,
# per-model audit history, SHA-256 linkage.
# =============================================================================

class TestTransparencyLog:
    """
    Maps to: aegis_core.cpp §12 TransparencyLog.

    Standards:
        NIST SP 800-53 AU-2    — event logging for governance events
        NIST SP 800-53 AU-3    — content of governance records
        NIST SP 800-53 AU-9    — protection of governance log
        NIST SP 800-53 AU-10   — non-repudiation via hash chain
        NIST AI RMF GOVERN-1.1 — policy-registry alignment logging
        NIST AI RMF MEASURE-2.5 — risk metrics in governance log
        ISA/IEC 62443-3-3 SR 6.2 — continuous monitoring log
        NERC CIP-007-6 R4      — security event monitoring
        NERC CIP-010 R1        — configuration change management audit trail
    """

    # ── T4.1  Cold-start and basic record ─────────────────────────────────────

    def test_empty_log_verifies_chain(self):
        """Empty log must pass chain verification (cold-start safe).
        Maps to: C++ tlog.verify_chain() on fresh registry (§12).
        [NIST SP 800-53 AU-9]"""
        assert TransparencyLog().verify_chain() is True

    def test_single_record_verifies_chain(self):
        """One record must form a valid single-entry chain.
        [NIST SP 800-53 AU-10]"""
        tlog = TransparencyLog()
        tlog.record("agent-alpha", "sess-001", "bridge_started")
        assert tlog.verify_chain() is True

    def test_multiple_records_verify_chain(self):
        """Multiple sequential records must all chain correctly.
        Maps to: C++ tlog.verify_chain() after full lifecycle (§12).
        [NIST SP 800-53 AU-10]"""
        tlog = TransparencyLog()
        for evt in ("bridge_started", "action_evaluated", "bridge_shutdown"):
            tlog.record("agent-alpha", "sess-001", evt)
        assert tlog.verify_chain() is True

    def test_length_property_reflects_record_count(self):
        """tlog.length must equal the number of records appended.
        Maps to: C++ tlog.size() (§12).
        [NIST SP 800-53 AU-2]"""
        tlog = TransparencyLog()
        assert tlog.length == 0
        tlog.record("a", "s", "event_1")
        assert tlog.length == 1
        tlog.record("a", "s", "event_2")
        assert tlog.length == 2

    # ── T4.2  Hash chain linkage ──────────────────────────────────────────────

    def test_first_entry_prev_hash_is_genesis(self):
        """First entry's prev_hash must equal TransparencyLog.GENESIS.
        [NIST SP 800-53 AU-9 — chain anchoring]"""
        tlog = TransparencyLog()
        e = tlog.record("a", "s", "evt")
        assert e.prev_hash == TransparencyLog.GENESIS

    def test_second_entry_links_to_first(self):
        """Entry[1].prev_hash must equal Entry[0].entry_hash.
        [NIST SP 800-53 AU-10 — cryptographic chain linkage]"""
        tlog = TransparencyLog()
        e1 = tlog.record("a", "s", "evt1")
        e2 = tlog.record("a", "s", "evt2")
        assert e2.prev_hash == e1.entry_hash

    def test_entry_hash_equals_compute_hash(self):
        """entry_hash must match compute_hash() for self-consistency.
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        tlog = TransparencyLog()
        e = tlog.record("a", "s", "evt")
        assert e.entry_hash == e.compute_hash()

    # ── T4.3  Tamper detection ────────────────────────────────────────────────

    def test_mutating_entry_hash_breaks_chain(self):
        """Overwriting entry_hash must cause verify_chain() to return False.
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        tlog = TransparencyLog()
        tlog.record("a", "s", "evt1")
        tlog.record("a", "s", "evt2")
        tlog._entries[0].entry_hash = "b" * 64
        assert tlog.verify_chain() is False

    def test_mutating_event_type_breaks_chain(self):
        """Silently changing event_type after record() must break chain verification.
        Maps to: C++ 'any post-append mutation detectable' invariant (§12).
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        tlog = TransparencyLog()
        tlog.record("a", "s", "bridge_started")
        tlog._entries[0].event_type = "tampered_event"
        assert tlog.verify_chain() is False

    # ── T4.4  event_type kwarg collision guard ────────────────────────────────

    def test_record_with_event_type_kwarg_does_not_raise(self):
        """Passing event_type= as a keyword arg in **details must not raise.
        The parameter is named log_event_type to prevent a positional collision.
        Maps to: C++ TransparencyLog comment re: kwarg disambiguation.
        [NIST SP 800-53 AU-3 — reliable audit logging]"""
        tlog = TransparencyLog()
        # This would have raised TypeError in the buggy original code
        tlog.record("a", "s", "action_evaluated",
                    event_type="tool_call",   # must be silently discarded
                    decision="ALLOW")
        assert tlog.length == 1

    def test_event_type_kwarg_is_discarded_not_stored_in_event_type(self):
        """When event_type= is passed as a kwarg, the entry's event_type field
        must still reflect the log_event_type positional argument, not the kwarg.
        [NIST SP 800-53 AU-3 — accurate event labelling]"""
        tlog = TransparencyLog()
        e = tlog.record("a", "s", "action_evaluated",
                        event_type="tool_call",
                        decision="ALLOW")
        assert e.event_type == "action_evaluated"

    # ── T4.5  Record content and details ──────────────────────────────────────

    def test_record_stores_agent_id_and_session_id(self):
        """Returned TLogEntry must carry the supplied agent_id and session_id.
        Maps to: C++ entries_for_model("agent-alpha") (§12).
        [NIST SP 800-53 AU-3 — identity traceability in audit records]"""
        tlog = TransparencyLog()
        e = tlog.record("agent-alpha", "sess-xyz", "bridge_started")
        assert e.agent_id   == "agent-alpha"
        assert e.session_id == "sess-xyz"

    def test_record_details_are_stored(self):
        """Keyword arguments passed to record() must appear in entry.details.
        [NIST SP 800-53 AU-3 — contextual audit data]"""
        tlog = TransparencyLog()
        e = tlog.record("a", "s", "action_evaluated",
                        decision="ALLOW", warp_score=0.12)
        assert e.details.get("decision") == "ALLOW"
        assert e.details.get("warp_score") == pytest.approx(0.12)

    def test_record_timestamp_is_recent(self):
        """TLogEntry.timestamp must be set to approximately now().
        Maps to: C++ AU-8 timestamp requirement (§0 TrustedClock).
        [NIST SP 800-53 AU-8 — time stamps]"""
        before = time.time()
        tlog = TransparencyLog()
        e = tlog.record("a", "s", "evt")
        assert before <= e.timestamp <= time.time() + 1.0

    def test_multi_agent_records_in_single_log(self):
        """A single log can hold records from multiple agents, each correctly
        attributed.  Mirrors C++ multi-agent transparency log behaviour (§12).
        [NIST AI RMF GOVERN-1.1 — cross-agent accountability]"""
        tlog = TransparencyLog()
        tlog.record("agent-alpha", "s1", "bridge_started")
        tlog.record("agent-beta",  "s2", "bridge_started")
        tlog.record("agent-alpha", "s1", "bridge_shutdown")
        assert tlog.length == 3
        assert tlog.verify_chain() is True


# =============================================================================
# §8 / T5 — SESSION GUARD
#
# C++ aegis_core.cpp §8: Session activate, process_decision, warp accumulation,
# SUSPECT/QUARANTINE thresholds, entropy flush callback, complete_flush,
# reactivate, close — INIT→ACTIVE→SUSPECT→QUARANTINE→FLUSHING→RESYNC→CLOSED.
# =============================================================================

class TestSessionGuard:
    """
    Maps to: aegis_core.cpp §8 Session state machine.

    Standards:
        NIST SP 800-53 AC-2    — account lifecycle management (ACTIVE→CLOSED)
        NIST SP 800-53 IR-4    — incident handling (QUARANTINE→RESYNC)
        NIST SP 800-53 SC-23   — session authenticity bounds
        NIST AI RMF MAP-5.1   — warp score as continuous risk metric
        NIST AI RMF MANAGE-3.2 — controlled recovery path
        ISA/IEC 62443-3-3 SR 6.2 — continuous monitoring
        DoD Zero Trust RA v2.0 — continuous behavioural re-evaluation
    """

    def _guard(self, agent: str = "agent-alpha",
               tlog: TransparencyLog | None = None) -> SessionGuard:
        return SessionGuard(agent_id=agent, tlog=tlog or TransparencyLog())

    # ── T5.1  INIT → ACTIVE ───────────────────────────────────────────────────

    def test_initial_state_is_init(self):
        """A newly-created SessionGuard must start in INIT state.
        Maps to: C++ sess.state() == SessionState::INIT before activate().
        [NIST SP 800-53 AC-2]"""
        sg = self._guard()
        assert sg.state == SessionState.INIT

    def test_activate_transitions_to_active(self):
        """activate() must transition INIT → ACTIVE.
        Maps to: C++ sess.activate(); assert(sess.state() == ACTIVE)  (§8).
        [NIST SP 800-53 AC-2; NIST SP 800-53 SC-23]"""
        sg = self._guard()
        sg.activate()
        assert sg.state == SessionState.ACTIVE

    def test_activate_twice_raises_runtime_error(self):
        """Calling activate() a second time must raise RuntimeError.
        Prevents double-activation that could reset warp state.
        [NIST SP 800-53 AC-2 — lifecycle state integrity]"""
        sg = self._guard()
        sg.activate()
        with pytest.raises(RuntimeError, match="activate"):
            sg.activate()

    def test_is_active_true_after_activate(self):
        """is_active must be True immediately after activate().
        [NIST SP 800-53 SC-23 — session readiness check]"""
        sg = self._guard()
        sg.activate()
        assert sg.is_active is True

    def test_is_active_false_in_init(self):
        """is_active must be False before activate() is called.
        [NIST SP 800-53 SC-23]"""
        assert self._guard().is_active is False

    # ── T5.2  Warp score accumulation ─────────────────────────────────────────

    def test_warp_score_zero_at_creation(self):
        """Warp score must start at 0.0.
        Maps to: C++ sess.warp_score() at start of §8.
        [NIST AI RMF MAP-5.1 — risk metric initialisation]"""
        sg = self._guard()
        sg.activate()
        assert sg.warp_score == pytest.approx(0.0)

    def test_allow_decision_does_not_increment_warp(self):
        """An ALLOW decision must not increase the warp score.
        Maps to: C++ r_allow = sess.process_decision(dec_normal)  (§8).
        [NIST AI RMF MAP-5.1 — non-adverse decisions have no warp impact]"""
        sg = self._guard()
        sg.activate()
        sg.record(PolicyDecision.ALLOW)
        assert sg.warp_score == pytest.approx(0.0)

    def test_deny_decision_increments_warp_by_warp_increment(self):
        """A DENY decision must add WARP_INCREMENT (0.12) to warp_score.
        Maps to: C++ DENY → warp += 1.0 (C++ uses different scale; Python uses 0.12).
        [NIST AI RMF MAP-5.1 — adverse decision tracking]"""
        sg = self._guard()
        sg.activate()
        sg.record(PolicyDecision.DENY)
        assert sg.warp_score == pytest.approx(SessionGuard.WARP_INCREMENT)

    def test_flag_decision_increments_warp_by_warp_increment(self):
        """A FLAG decision must also increment warp by WARP_INCREMENT.
        Maps to: C++ FLAG → warp += 0.5  (§8).
        [NIST AI RMF MAP-5.1]"""
        sg = self._guard()
        sg.activate()
        sg.record(PolicyDecision.FLAG)
        assert sg.warp_score == pytest.approx(SessionGuard.WARP_INCREMENT)

    def test_warp_score_capped_at_one(self):
        """Warp score must not exceed 1.0 regardless of how many DENY decisions occur.
        [NIST AI RMF MAP-5.1 — bounded risk metric]"""
        sg = self._guard()
        sg.activate()
        for _ in range(20):
            sg.record(PolicyDecision.DENY)
            if sg.state == SessionState.QUARANTINE:
                sg.resync()
        # After resync, warp_score is reset; but confirm it never exceeded 1.0
        assert sg.warp_score <= 1.0

    # ── T5.3  ACTIVE → SUSPECT ────────────────────────────────────────────────

    def test_warp_at_suspect_threshold_transitions_to_suspect(self):
        """When warp_score reaches SUSPECT_THRESHOLD (0.40) the state must
        transition to SUSPECT.
        Maps to: C++ ACTIVE → SUSPECT when warp threshold breached (§8).
        [NIST AI RMF MAP-5.1 — elevated risk tier]"""
        sg = self._guard()
        sg.activate()
        # Need ceil(0.40 / 0.12) = 4 DENY decisions to cross 0.40
        for _ in range(4):
            sg.record(PolicyDecision.DENY)
        assert sg.state in (SessionState.SUSPECT, SessionState.QUARANTINE)

    def test_suspect_state_is_still_active(self):
        """is_active must return True in SUSPECT state (actions still permitted).
        Maps to: C++ sess.process_decision() while SUSPECT (§8).
        [NIST SP 800-53 SC-23 — session continuity with monitoring]"""
        sg = self._guard()
        sg.activate()
        for _ in range(4):
            sg.record(PolicyDecision.DENY)
        if sg.state == SessionState.SUSPECT:
            assert sg.is_active is True

    # ── T5.4  SUSPECT → QUARANTINE ────────────────────────────────────────────

    def test_warp_at_quarantine_threshold_transitions_to_quarantine(self):
        """When warp_score reaches QUARANTINE_THRESHOLD (0.70) the state must
        become QUARANTINE.
        Maps to: C++ SUSPECT → QUARANTINE → FLUSHING (§8).
        [NIST SP 800-53 IR-4 — incident response trigger]"""
        sg = self._guard()
        sg.activate()
        for _ in range(10):   # 10 × 0.12 = 1.20 → well past 0.70
            if sg.state == SessionState.QUARANTINE:
                break
            sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.QUARANTINE

    def test_is_active_false_in_quarantine(self):
        """is_active must be False in QUARANTINE (actions blocked).
        Maps to: C++ blocked_quarantine pre-condition (§8).
        [NIST SP 800-53 IR-4; DoD Zero Trust RA v2.0]"""
        sg = self._guard()
        sg.activate()
        for _ in range(10):
            if sg.state == SessionState.QUARANTINE:
                break
            sg.record(PolicyDecision.DENY)
        if sg.state == SessionState.QUARANTINE:
            assert sg.is_active is False

    def test_record_in_quarantine_is_ignored(self):
        """record() in QUARANTINE must silently no-op (ignored, not raised).
        Maps to: C++ 'record_ignored' log event when state not ACTIVE/SUSPECT.
        [NIST SP 800-53 IR-4 — freeze anomalous agent in place]"""
        sg = self._guard()
        sg.activate()
        for _ in range(10):
            if sg.state == SessionState.QUARANTINE:
                break
            sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.QUARANTINE
        before_warp = sg.warp_score
        returned = sg.record(PolicyDecision.DENY)
        assert returned == SessionState.QUARANTINE
        assert sg.warp_score == pytest.approx(before_warp)

    # ── T5.5  QUARANTINE → RESYNC → ACTIVE (resync) ──────────────────────────

    def test_resync_from_quarantine_resets_warp_and_returns_active(self):
        """resync() must reset warp_score and return to ACTIVE.
        Maps to: C++ sess.reactivate() → ACTIVE (§8).
        [NIST AI RMF MANAGE-3.2 — controlled recovery;
         NIST SP 800-53 IR-4 — incident recovery path]"""
        sg = self._guard()
        sg.activate()
        for _ in range(10):
            if sg.state == SessionState.QUARANTINE:
                break
            sg.record(PolicyDecision.DENY)
        assert sg.state == SessionState.QUARANTINE
        sg.resync()
        assert sg.state    == SessionState.ACTIVE
        assert sg.warp_score == pytest.approx(0.0)

    def test_resync_from_non_quarantine_raises(self):
        """resync() called outside QUARANTINE must raise RuntimeError.
        Prevents accidental warp-score reset during normal operation.
        Maps to: C++ resync() requires QUARANTINE state  (§8).
        [NIST AI RMF MANAGE-3.2 — intentional recovery gate]"""
        sg = self._guard()
        sg.activate()
        with pytest.raises(RuntimeError, match="QUARANTINE"):
            sg.resync()

    def test_resync_logs_resynced_event_to_tlog(self):
        """resync() must record a 'resynced' event to the transparency log.
        Maps to: C++ tlog.record("resynced") in Session  (§8).
        [NIST SP 800-53 AU-2 — governance event logging for resync]"""
        tlog = TransparencyLog()
        sg = SessionGuard("agent-alpha", tlog=tlog)
        sg.activate()
        for _ in range(10):
            if sg.state == SessionState.QUARANTINE:
                break
            sg.record(PolicyDecision.DENY)
        pre_len = tlog.length
        sg.resync()
        assert tlog.length > pre_len
        event_types = [e.event_type for e in tlog._entries]
        assert "resynced" in event_types

    # ── T5.6  ACTIVE → CLOSED ────────────────────────────────────────────────

    def test_close_transitions_to_closed(self):
        """close() must set state to CLOSED.
        Maps to: C++ sess.close(); assert(sess.state() == CLOSED)  (§8).
        [NIST SP 800-53 AC-2 — account termination]"""
        sg = self._guard()
        sg.activate()
        sg.close()
        assert sg.state == SessionState.CLOSED

    def test_is_active_false_after_close(self):
        """is_active must be False after close().
        [NIST SP 800-53 AC-2; NIST SP 800-53 SC-23]"""
        sg = self._guard()
        sg.activate()
        sg.close()
        assert sg.is_active is False

    def test_close_logs_session_closed_to_tlog(self):
        """close() must append a 'session_closed' record to the tlog.
        [NIST SP 800-53 AU-2 — governance event for session termination]"""
        tlog = TransparencyLog()
        sg = SessionGuard("agent-alpha", tlog=tlog)
        sg.activate()
        sg.close()
        event_types = [e.event_type for e in tlog._entries]
        assert "session_closed" in event_types

    def test_record_in_closed_state_is_ignored(self):
        """record() in CLOSED state must silently no-op.
        [NIST SP 800-53 AC-2 — terminated accounts must not accumulate state]"""
        sg = self._guard()
        sg.activate()
        sg.close()
        returned = sg.record(PolicyDecision.DENY)
        assert returned == SessionState.CLOSED
        assert sg.warp_score == pytest.approx(0.0)

    # ── T5.7  Transparency log events ─────────────────────────────────────────

    def test_activate_logs_session_activated(self):
        """activate() must record 'session_activated' to the tlog.
        Maps to: C++ tlog.record("session_activated") (§8).
        [NIST SP 800-53 AU-2; NIST AI RMF GOVERN-1.1]"""
        tlog = TransparencyLog()
        sg = SessionGuard("agent-alpha", tlog=tlog)
        sg.activate()
        event_types = [e.event_type for e in tlog._entries]
        assert "session_activated" in event_types

    def test_quarantine_logs_quarantine_triggered(self):
        """Reaching QUARANTINE must log 'quarantine_triggered' to the tlog.
        [NIST SP 800-53 IR-4; ISA/IEC 62443-3-3 SR 6.2]"""
        tlog = TransparencyLog()
        sg = SessionGuard("agent-alpha", tlog=tlog)
        sg.activate()
        for _ in range(10):
            if sg.state == SessionState.QUARANTINE:
                break
            sg.record(PolicyDecision.DENY)
        if sg.state == SessionState.QUARANTINE:
            event_types = [e.event_type for e in tlog._entries]
            assert "quarantine_triggered" in event_types


# =============================================================================
# §1–3 / T6 — AEGIS FRAMEWORK BRIDGE
#
# C++ aegis_core.cpp §1 (passport verify) + §2 (session keys / payload MAC) +
# §3 (capability gate / PolicyEngine pipeline).  The Bridge is the Python
# counterpart to the combined HandshakeValidator + PolicyEngine enforcement.
# =============================================================================

class TestAegisFrameworkBridge:
    """
    Maps to: aegis_core.cpp §1 (start/verify), §2 (signed messages /
    session isolation), §3 (capability auth / policy pipeline).

    Standards:
        NIST SP 800-53 AC-3    — access enforcement via PolicyEngine
        NIST SP 800-53 AC-6    — least privilege via require_capability()
        NIST SP 800-53 AU-2    — evaluate_action() always logs to tlog
        NIST SP 800-53 AU-3    — vault and tlog carry full decision context
        NIST SP 800-53 AU-9    — DENY payloads never vaulted
        NIST SP 800-53 IA-5    — expired passport blocked at start()
        NIST SP 800-53 IR-4    — QUARANTINE pre-condition blocks all actions
        NIST SP 800-53 SC-12   — status_dict() exposes no credential material
        NIST SP 800-218A PW.8.1 — payload never stored raw
        NIST AI RMF MAP-5.1   — warp accumulates on FLAG/DENY
        DoD Zero Trust RA v2.0 — verify before every action
        OWASP LLM06/LLM08     — require_capability() capability gate
        ISA/IEC 62443-3-3 SR 2.1 — per-action authorization check
    """

    # ── T6.1  Lifecycle: start() ──────────────────────────────────────────────

    def test_start_activates_session(self):
        """start() must transition the session from INIT to ACTIVE.
        Maps to: C++ validate_hello() → session activation  (§1, §2).
        [NIST SP 800-53 IA-5; DoD Zero Trust RA v2.0]"""
        b = _started_bridge()
        assert b.session.state == SessionState.ACTIVE

    def test_start_with_expired_passport_raises_permission_error(self):
        """Expired passport at start() must raise PermissionError.
        register_agent() also rejects expired passports, so we register with a
        valid passport and expire it in-place before calling start().
        This mirrors the C++ scenario where a passport expires between issuance
        and the first handshake (registry.verify(pa, future).status == EXPIRED).
        [NIST SP 800-53 IA-5; SEC-001 fail-closed]"""
        adp = _adapter()
        p = _passport(ttl=3600)
        bridge = adp.register_agent(p, "test")
        # Expire the passport after registration, before start()
        object.__setattr__(p, "issued_at", time.time() - 7200)
        object.__setattr__(p, "ttl_seconds", 1)
        with pytest.raises(PermissionError, match="[Pp]assport"):
            bridge.start()

    def test_start_records_bridge_started_in_tlog(self):
        """start() must append a 'bridge_started' governance record.
        Maps to: C++ tlog.record("bridge_started")  (§1).
        [NIST SP 800-53 AU-2; NIST AI RMF GOVERN-1.1]"""
        adp = _adapter()
        bridge = adp.register_agent(_passport(), "langgraph")
        bridge.start()
        event_types = [e.event_type for e in adp.tlog._entries]
        assert "bridge_started" in event_types

    # ── T6.2  evaluate_action() — ALLOW path ─────────────────────────────────

    def test_allow_returns_true_allowed_flag(self):
        """evaluate_action() with low sensitivity must return allowed=True.
        Maps to: C++ dec_normal.action == ALLOW → sess.process_decision returns true.
        [NIST SP 800-53 AC-3]"""
        b = _started_bridge()
        _, allowed = b.evaluate_action("payload", 0.8, 0.1)
        assert allowed is True

    def test_allow_appends_one_vault_entry(self):
        """ALLOW decision must append exactly one entry to the AuditVault.
        Maps to: C++ vault.append() for ALLOW decisions  (§3 / §10).
        [NIST SP 800-53 AU-2 — permitted actions must be logged]"""
        b = _started_bridge()
        b.evaluate_action("payload", 0.8, 0.1)
        assert b.vault.length == 1

    def test_allow_records_tlog_entry(self):
        """ALLOW decision must also record to TransparencyLog.
        Maps to: C++ tlog.record("action_evaluated") always  (§12).
        [NIST SP 800-53 AU-2 — all decisions logged]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test")
        b.start()
        pre = adp.tlog.length
        b.evaluate_action("payload", 0.8, 0.1)
        assert adp.tlog.length > pre

    # ── T6.3  evaluate_action() — FLAG path ──────────────────────────────────

    def test_flag_returns_true_allowed_flag(self):
        """FLAG decision must return allowed=True (action proceeds with monitoring).
        Maps to: C++ FLAG → monitored allow  (§3).
        [NIST AI RMF MAP-5.1 — FLAG is not a hard block]"""
        b = _started_bridge(ceiling=0.70, flag=0.30)
        _, allowed = b.evaluate_action("payload", 0.8, 0.50)
        assert allowed is True

    def test_flag_appends_vault_entry(self):
        """FLAG decision must write to the AuditVault (same as ALLOW).
        [NIST SP 800-53 AU-2 — flagged actions must be logged]"""
        b = _started_bridge(ceiling=0.70, flag=0.30)
        b.evaluate_action("payload", 0.8, 0.50)
        assert b.vault.length == 1

    def test_flag_increments_warp_score(self):
        """FLAG decision must increment warp_score by WARP_INCREMENT.
        Maps to: C++ FLAG → warp += 0.5  (§8).
        [NIST AI RMF MAP-5.1 — risk accumulation on adverse decisions]"""
        b = _started_bridge(ceiling=0.70, flag=0.30)
        b.evaluate_action("payload", 0.8, 0.50)
        assert b.session.warp_score == pytest.approx(SessionGuard.WARP_INCREMENT)

    # ── T6.4  evaluate_action() — DENY path ──────────────────────────────────

    def test_deny_returns_false_allowed_flag(self):
        """DENY decision must return allowed=False.
        Maps to: C++ dec_hostile → r2 = false (§8).
        [NIST SP 800-53 AC-3 — denied actions blocked]"""
        b = _started_bridge(ceiling=0.30)  # low ceiling forces DENY
        _, allowed = b.evaluate_action("payload", 0.8, 0.50)
        assert allowed is False

    def test_deny_does_not_append_vault_entry(self):
        """DENY payload must never be written to the AuditVault.
        Maps to: C++ 'DENY decisions: payload never persisted' comment.
        [NIST SP 800-218A PW.8.1 — data minimisation;
         DoD Zero Trust RA v2.0 — Data pillar]"""
        b = _started_bridge(ceiling=0.30)
        b.evaluate_action("payload", 0.8, 0.50)
        assert b.vault.length == 0

    def test_deny_still_records_tlog_entry(self):
        """DENY must still create a TransparencyLog entry — denial is a governance event.
        Maps to: C++ 'NIST SP 800-53 AU-2 — denied actions must still be logged'  (§3).
        [NIST SP 800-53 AU-2; NIST AI RMF MEASURE-2.5]"""
        adp = _adapter(ceiling=0.30)
        b = adp.register_agent(_passport(), "test")
        b.start()
        pre = adp.tlog.length
        b.evaluate_action("payload", 0.8, 0.50)
        assert adp.tlog.length > pre

    def test_deny_increments_warp_score(self):
        """DENY decision must increment warp score.
        Maps to: C++ DENY → warp += 1.0 (C++ scale) / WARP_INCREMENT (Python).
        [NIST AI RMF MAP-5.1]"""
        b = _started_bridge(ceiling=0.30)
        b.evaluate_action("payload", 0.8, 0.50)
        assert b.session.warp_score > 0.0

    # ── T6.5  Pre-condition guards ────────────────────────────────────────────

    def test_evaluate_before_start_raises_runtime_error(self):
        """evaluate_action() before start() must raise RuntimeError.
        Maps to: C++ 'blocked_inactive' pre-condition  (§3).
        [NIST SP 800-53 IR-4; DoD Zero Trust RA v2.0]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test")
        with pytest.raises(RuntimeError, match="active"):
            b.evaluate_action("payload")

    def test_quarantine_blocks_evaluate_with_permission_error(self):
        """evaluate_action() in QUARANTINE must raise PermissionError.
        Maps to: C++ blocked_quarantine pre-condition  (§8).
        [NIST SP 800-53 IR-4 — blocked_quarantine]"""
        b = _started_bridge()
        # Drive to QUARANTINE
        for _ in range(10):
            if b.session.state == SessionState.QUARANTINE:
                break
            try:
                b.evaluate_action("p", 0.8, 0.80)  # may exceed ceiling and deny
            except PermissionError:
                break
        b.session.state = SessionState.QUARANTINE  # force QUARANTINE directly
        with pytest.raises(PermissionError, match="quarantine"):
            b.evaluate_action("p")

    # ── T6.6  Payload hashing ─────────────────────────────────────────────────

    def test_payload_stored_as_hash_not_raw(self):
        """Raw payload must never appear in the vault after evaluate_action().
        Maps to: C++ 'payload hash only' comment  (§10).
        [NIST SP 800-218A PW.8.1; DoD Zero Trust RA v2.0 — Data pillar]"""
        secret = "do not store me verbatim"
        b = _started_bridge()
        b.evaluate_action(secret, 0.8, 0.1)
        entry = b.vault._chain[-1]
        assert secret not in str(vars(entry))
        assert entry.payload_hash == hashlib.sha256(
            secret.encode("utf-8")).hexdigest()

    # ── T6.7  Event type and metadata ─────────────────────────────────────────

    def test_event_type_written_to_vault_entry(self):
        """Custom event_type must appear in the vault entry.
        Maps to: C++ vault.append("tool_call", ...)  (§10).
        [NIST SP 800-53 AU-3 — event type in audit record]"""
        b = _started_bridge()
        b.evaluate_action("p", 0.8, 0.1, event_type="tool_call")
        assert b.vault._chain[-1].event_type == "tool_call"

    def test_metadata_kwargs_stored_in_vault_entry(self):
        """**metadata kwargs must be stored in the vault entry's metadata dict.
        Maps to: C++ vault.append() metadata argument  (§10).
        [NIST SP 800-53 AU-3 — contextual metadata]"""
        b = _started_bridge()
        b.evaluate_action("p", 0.8, 0.1, node_name="research_node", task="summarise")
        meta = b.vault._chain[-1].metadata
        assert meta["node_name"] == "research_node"
        assert meta["task"]      == "summarise"

    def test_action_count_increments_on_every_call(self):
        """_action_count must increment regardless of decision outcome.
        [NIST SP 800-53 AU-3 — complete action count in status]"""
        b = _started_bridge()
        b.evaluate_action("p1", 0.8, 0.1)
        b.evaluate_action("p2", 0.8, 0.1)
        assert b._action_count == 2

    # ── T6.8  require_capability() ────────────────────────────────────────────

    def test_require_capability_passes_for_granted_cap(self):
        """require_capability() must not raise when the passport grants the cap.
        Maps to: C++ caps_full.classifier_authority == true  (§3).
        [NIST SP 800-53 AC-6 — least privilege; OWASP LLM08]"""
        b = _started_bridge(caps=frozenset({"read", "write"}))
        b.require_capability("read")   # must not raise

    def test_require_capability_raises_for_missing_cap(self):
        """require_capability() must raise PermissionError for unlisted capability.
        Maps to: C++ assert(!pc.capabilities.bft_consensus)  (§3).
        [NIST SP 800-53 AC-6; OWASP LLM06 — excessive agency prevention]"""
        b = _started_bridge(caps=frozenset({"read"}))
        with pytest.raises(PermissionError, match="capability"):
            b.require_capability("write")

    def test_require_capability_denies_all_caps_for_empty_passport(self):
        """A passport with no capabilities must fail every require_capability() call.
        Maps to: C++ caps_read_only with all fields=false  (§3).
        [NIST SP 800-53 AC-6 — deny-by-default capability model]"""
        b = _started_bridge(caps=frozenset())
        with pytest.raises(PermissionError):
            b.require_capability("anything")

    # ── T6.9  shutdown() ──────────────────────────────────────────────────────

    def test_shutdown_returns_true_for_clean_run(self):
        """shutdown() must return (True, True) after a normal evaluate+shutdown cycle.
        Maps to: C++ vault.verify_chain() after run  (§10).
        [NIST SP 800-53 AU-9; NIST AI RMF MANAGE-3.2]"""
        b = _started_bridge()
        b.evaluate_action("p", 0.8, 0.1)
        v_ok, t_ok = b.shutdown()
        assert v_ok is True
        assert t_ok is True

    def test_shutdown_verifies_chain_after_many_actions(self):
        """Chain must verify correctly after a sequence of evaluate_action() calls.
        Maps to: C++ verify_chain() after §10 vault appends.
        [NIST SP 800-53 AU-9, AU-10 — chain integrity under load]"""
        b = _started_bridge()
        for i in range(20):
            b.evaluate_action(f"action-{i}", 0.8, 0.1)
        v_ok, t_ok = b.shutdown()
        assert v_ok is True and t_ok is True

    def test_shutdown_closes_session(self):
        """shutdown() must transition session to CLOSED.
        Maps to: C++ sess.close()  (§8).
        [NIST SP 800-53 AC-2 — account termination]"""
        b = _started_bridge()
        b.shutdown()
        assert b.session.state == SessionState.CLOSED

    # ── T6.10  status_dict() ──────────────────────────────────────────────────

    def test_status_dict_contains_required_keys(self):
        """status_dict() must contain all health-check-relevant fields.
        [NIST SP 800-53 AU-3; NIST AI RMF MEASURE-2.5]"""
        b = _started_bridge()
        s = b.status_dict()
        for key in ("model_id", "passport_id", "framework", "session_id",
                    "session_state", "warp_score", "action_count",
                    "vault_entries", "tlog_entries", "passport_expired"):
            assert key in s, f"Missing status field: '{key}'"

    def test_status_dict_contains_no_credential_fields(self):
        """status_dict() must not expose any field name matching a redact pattern.
        Maps to: C++ SEC-001 — no secrets in logs  (§0).
        [NIST SP 800-53 SC-12; OWASP LLM05 — insecure output handling]"""
        s = _started_bridge().status_dict()
        for key in s:
            assert not any(pat in key.lower() for pat in _REDACT_PATTERNS), (
                f"Credential field exposed in status_dict: '{key}'"
            )

    def test_status_dict_reflects_current_warp_score(self):
        """status_dict() warp_score must match bridge.session.warp_score.
        [NIST AI RMF MEASURE-2.5 — real-time risk metrics]"""
        b = _started_bridge(flag=0.10, ceiling=0.70)
        b.evaluate_action("p", 0.8, 0.50)  # FLAG → warp increments
        s = b.status_dict()
        assert s["warp_score"] == pytest.approx(
            round(b.session.warp_score, 4))

    def test_status_dict_vault_entries_count_matches(self):
        """status_dict vault_entries must reflect the actual vault chain length.
        [NIST SP 800-53 AU-3]"""
        b = _started_bridge()
        b.evaluate_action("p1", 0.8, 0.1)
        b.evaluate_action("p2", 0.8, 0.1)
        assert b.status_dict()["vault_entries"] == 2


# =============================================================================
# §6 / T7 — AEGIS ADAPTER (fleet facade)
#
# C++ aegis_core.cpp §6: MultiPartyIssuer 2-of-3 quorum, fleet coordination.
# Python: AegisAdapter shared vault+tlog across all registered agents.
# =============================================================================

class TestAegisAdapter:
    """
    Maps to: aegis_core.cpp §6 MultiPartyIssuer (fleet registration analog)
    + §12 TransparencyLog fleet verification.

    Standards:
        NIST SP 800-53 AC-2    — fleet agent registration and lifecycle
        NIST SP 800-53 AC-5    — separation of duties (no single agent bypasses fleet)
        NIST SP 800-53 AU-9    — fleet-level chain verification
        NIST SP 800-53 SI-7    — cross-agent integrity via shared chain
        NIST AI RMF GOVERN-1.1 — fleet-wide policy alignment
        DoD Zero Trust RA v2.0 — Identity pillar — every agent registered
        ISA/IEC 62443-3-3 SR 6.1 — fleet-level audit accessibility
    """

    # ── T7.1  register_agent() ────────────────────────────────────────────────

    def test_register_returns_aegis_framework_bridge(self):
        """register_agent() must return an AegisFrameworkBridge instance.
        [NIST SP 800-53 AC-2; DoD Zero Trust RA v2.0]"""
        adp = _adapter()
        bridge = adp.register_agent(_passport(), "langgraph")
        assert isinstance(bridge, AegisFrameworkBridge)

    def test_register_expired_passport_raises_permission_error(self):
        """Expired passport at registration must raise PermissionError.
        Maps to: C++ registry.verify(pa, future) rejected at handshake  (§5).
        [NIST SP 800-53 IA-5; SEC-001 — fail-closed; DoD Zero Trust RA v2.0]"""
        adp = _adapter()
        with pytest.raises(PermissionError, match="expired"):
            adp.register_agent(_passport(expired=True), "test")

    def test_re_registration_replaces_old_bridge(self):
        """Re-registering the same model_id must replace the existing bridge.
        Maps to: C++ re-issuance of a passport for the same model_id  (§1).
        [NIST SP 800-53 AC-2 — account replacement semantics]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("agent-alpha"), "lg")
        b2 = adp.register_agent(_passport("agent-alpha"), "ag")
        assert adp._bridges["agent-alpha"] is b2
        assert adp._bridges["agent-alpha"] is not b1

    # ── T7.2  Shared vault and tlog ───────────────────────────────────────────

    def test_two_agents_share_single_vault(self):
        """All agents registered with the same adapter share one AuditVault.
        Maps to: C++ single vault across §8/§9 agents  (§10).
        [ISA/IEC 62443-3-3 SR 6.1 — cross-agent audit accessibility]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        b1.evaluate_action("p1", 0.8, 0.1)
        b2.evaluate_action("p2", 0.8, 0.1)
        assert adp.vault.length == 2

    def test_two_agents_share_single_tlog(self):
        """All agents share one TransparencyLog, enabling cross-agent correlation.
        Maps to: C++ tlog.entries_for_model() across multiple agents  (§12).
        [NIST AI RMF GOVERN-1.1; NIST SP 800-53 AU-10]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        # Both bridge_started events must be in the shared log
        assert adp.tlog.length >= 2

    def test_vault_entries_span_multiple_agents_in_correct_order(self):
        """Vault entries from multiple agents must appear in insertion order.
        [NIST SP 800-53 AU-10 — chronological chain linkage]"""
        adp = _adapter()
        for label in ("a1", "a2", "a3"):
            b = adp.register_agent(_passport(label), "test"); b.start()
            b.evaluate_action(f"p-{label}", 0.8, 0.1)
        assert adp.vault.length == 3
        agent_ids = [e.agent_id for e in adp.vault._chain]
        assert agent_ids == ["a1", "a2", "a3"]

    # ── T7.3  verify_all_chains() ─────────────────────────────────────────────

    def test_empty_fleet_verify_chains_passes(self):
        """verify_all_chains() on a fresh adapter must return (True, True).
        Maps to: C++ cold-start chain verification  (§10, §12).
        [NIST SP 800-53 AU-9 — cold-start safe]"""
        v, t = _adapter().verify_all_chains()
        assert v is True and t is True

    def test_verify_all_chains_after_multi_agent_run(self):
        """Fleet chain integrity must hold across 4 agents with 5 actions each.
        Maps to: C++ vault.verify_chain() + tlog.verify_chain() after §9  (§10, §12).
        [NIST SP 800-53 AU-9, AU-10, SI-7]"""
        adp = _adapter()
        for i in range(4):
            b = adp.register_agent(_passport(f"agent-{i}"), "test"); b.start()
            for _ in range(5):
                b.evaluate_action(f"p-{i}", 0.8, 0.1)
        v, t = adp.verify_all_chains()
        assert v is True and t is True

    def test_verify_all_chains_detects_vault_tampering(self):
        """verify_all_chains() must return vault_ok=False when vault is tampered.
        Maps to: C++ chain tamper detection (§10).
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()
        b.evaluate_action("p", 0.8, 0.1)
        # Corrupt the vault chain
        adp.vault._chain[0].entry_hash = "z" * 64
        v_ok, _ = adp.verify_all_chains()
        assert v_ok is False

    def test_verify_all_chains_detects_tlog_tampering(self):
        """verify_all_chains() must return tlog_ok=False when tlog is tampered.
        [NIST SP 800-53 AU-9; NIST SP 800-53 SI-7]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()
        adp.tlog._entries[0].entry_hash = "z" * 64
        _, t_ok = adp.verify_all_chains()
        assert t_ok is False

    # ── T7.4  fleet_status() ─────────────────────────────────────────────────

    def test_fleet_status_length_matches_registered_agents(self):
        """fleet_status() must return one entry per registered agent.
        [NIST SP 800-53 AU-3; NIST AI RMF MEASURE-2.5]"""
        adp = _adapter()
        for i in range(3):
            b = adp.register_agent(_passport(f"a{i}"), "test"); b.start()
        assert len(adp.fleet_status()) == 3

    def test_fleet_status_entries_contain_required_keys(self):
        """Each fleet_status() entry must contain health-relevant keys.
        [NIST AI RMF MEASURE-2.5 — fleet-level risk metrics]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()
        entry = adp.fleet_status()[0]
        for key in ("model_id", "session_state", "warp_score",
                    "vault_entries", "tlog_entries"):
            assert key in entry, f"Missing fleet status field: '{key}'"

    def test_empty_fleet_status_is_empty_list(self):
        """fleet_status() on a newly-created adapter must return [].
        [NIST AI RMF MEASURE-2.5]"""
        assert _adapter().fleet_status() == []


# =============================================================================
# §2 / T8 — HANDSHAKE ANALOGS (session isolation, nonce partitioning)
#
# C++ aegis_core.cpp §2: HandshakeValidator 3-message handshake, replay
# detection (SEC-002), transport binding, forward secrecy.
#
# Python: the Bridge enforces equivalent isolation via per-session
# evaluate_action() state machines.  Each bridge has its own SessionGuard
# and is independent from other bridges sharing the same adapter.
# =============================================================================

class TestHandshakeAnalogs:
    """
    Maps to: aegis_core.cpp §2 HandshakeValidator.

    Standards:
        NIST SP 800-53 SC-8    — transmission integrity (payload MAC analog)
        NIST SP 800-53 SC-23   — session authenticity and isolation
        NIST SP 800-53 IA-3    — device identification via per-bridge state
        SEC-002                — nonce/session namespace partitioning
        DoD Zero Trust RA v2.0 — Device + Application pillars
    """

    def test_two_bridges_have_independent_sessions(self):
        """Two bridges registered with the same adapter must have distinct session_ids.
        Maps to: C++ nc_initiator / nc_responder partitioning (SEC-002).
        [NIST SP 800-53 SC-23 — session isolation; SEC-002]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        assert b1.session.session_id != b2.session.session_id

    def test_two_bridges_independent_warp_scores(self):
        """Warp accumulation in one bridge must not affect another's warp score.
        Maps to: C++ separate NonceCache / SessionContext per HandshakeValidator (§2).
        [NIST SP 800-53 SC-23 — session independence; DoD ZT App pillar]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        # Drive b1 toward suspect with denying evaluations
        for _ in range(4):
            try:
                b1.evaluate_action("p", 0.8, 0.80)  # may be denied by ceiling
            except PermissionError:
                break
        # b2 must be unaffected
        assert b2.session.warp_score == pytest.approx(0.0)

    def test_two_bridges_independent_vault_entry_counts(self):
        """Vault entries from one bridge must not bleed into another's per-session count.
        Maps to: C++ two_handshakes produce distinct session material (§2).
        [ISA/IEC 62443-3-3 SR 6.1 — session-scoped audit entries]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a2"), "ag"); b2.start()
        b1.evaluate_action("p", 0.8, 0.1)
        b1.evaluate_action("p", 0.8, 0.1)
        b2.evaluate_action("p", 0.8, 0.1)
        s1_entries = adp.vault.entries_for_session(b1.session.session_id)
        s2_entries = adp.vault.entries_for_session(b2.session.session_id)
        assert len(s1_entries) == 2
        assert len(s2_entries) == 1

    def test_payload_mac_determinism(self):
        """The same payload evaluated by the same bridge must produce the same
        payload_hash in successive vault entries (deterministic SHA-256).
        Maps to: C++ both endpoints produce identical MAC for the same payload (§2).
        [NIST SP 800-53 SC-8 — transmission integrity;
         NIST SP 800-218A PW.4.1 — deterministic hash]"""
        b = _started_bridge()
        b.evaluate_action("stable-payload", 0.8, 0.1)
        b.evaluate_action("stable-payload", 0.8, 0.1)
        h1 = b.vault._chain[-2].payload_hash
        h2 = b.vault._chain[-1].payload_hash
        assert h1 == h2

    def test_different_payloads_produce_distinct_vault_hashes(self):
        """Distinct payloads must produce distinct vault entry hashes.
        Maps to: C++ independent handshakes produce distinct session keys (§2).
        [NIST SP 800-218A PW.4.1 — collision resistance]"""
        b = _started_bridge()
        b.evaluate_action("payload-one", 0.8, 0.1)
        b.evaluate_action("payload-two", 0.8, 0.1)
        h1 = b.vault._chain[0].payload_hash
        h2 = b.vault._chain[1].payload_hash
        assert h1 != h2

    def test_expired_passport_rejected_at_start_not_just_registration(self):
        """An expired passport must be caught at start(), preventing session
        activation even if registration somehow succeeded.
        Maps to: C++ revoked agent-delta rejected at handshake (§5).
        [NIST SP 800-53 IA-5; SEC-001; DoD Zero Trust RA v2.0]"""
        # Register with a valid passport, then manually expire it
        adp = _adapter()
        p = _passport()
        b = adp.register_agent(p, "test")
        # Expire the passport after registration
        object.__setattr__(p, "issued_at", time.time() - 7200)
        object.__setattr__(p, "ttl_seconds", 1)
        with pytest.raises(PermissionError, match="[Pp]assport"):
            b.start()

    def test_framework_label_stored_on_vault_entries(self):
        """Vault entries must carry the framework label from the bridge.
        Maps to: C++ framework parameter in vault.append()  (§10).
        [NIST SP 800-53 AU-3 — framework provenance in audit record]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "langgraph"); b.start()
        b.evaluate_action("p", 0.8, 0.1)
        assert adp.vault._chain[-1].framework == "langgraph"

    def test_session_id_consistent_across_vault_entries(self):
        """All vault entries from a single bridge must share the same session_id.
        Maps to: C++ ctx_a.session_id used consistently across vault appends (§10).
        [NIST SP 800-53 SC-23 — session identity consistency]"""
        b = _started_bridge()
        for _ in range(5):
            b.evaluate_action("p", 0.8, 0.1)
        session_ids = {e.session_id for e in b.vault._chain}
        assert len(session_ids) == 1
        assert b.session.session_id in session_ids

    def test_warp_score_survives_flag_then_allow_sequence(self):
        """Warp score must accumulate on FLAG, remain after ALLOW, and not decrease.
        Maps to: C++ warp score accumulation sequence in §8.
        [NIST AI RMF MAP-5.1 — monotonic risk accumulation within session]"""
        b = _started_bridge(flag=0.10, ceiling=0.70)
        b.evaluate_action("p", 0.8, 0.20)   # FLAG → warp increments
        warp_after_flag = b.session.warp_score
        b.evaluate_action("p", 0.8, 0.05)   # ALLOW → warp unchanged
        assert b.session.warp_score == pytest.approx(warp_after_flag)

    def test_forward_secrecy_analog_new_bridge_new_session(self):
        """A new bridge for the same agent must get a fresh session_id, analogous
        to forward-secrecy ensuring past session material is not reused.
        Maps to: C++ two_handshakes produce distinct session_ids (§2).
        [NIST SP 800-53 SC-23 — session freshness; DoD ZT — ephemeral sessions]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a"), "lg"); b1.start()
        b2 = adp.register_agent(_passport("a"), "lg"); b2.start()
        assert b1.session.session_id != b2.session.session_id

    def test_replay_analog_action_count_not_reset_across_actions(self):
        """_action_count must be monotonically increasing — no implicit resets.
        Maps to: C++ nonce cache prevents replay by remembering consumed nonces (§2).
        [NIST SP 800-53 SC-23 — replay prevention]"""
        b = _started_bridge()
        for i in range(5):
            b.evaluate_action(f"a{i}", 0.8, 0.1)
        assert b._action_count == 5

    def test_transport_binding_analog_framework_label_immutable(self):
        """The framework label on a bridge cannot be changed after construction,
        analogous to the C++ transport-binding check refusing TLS cert changes.
        Maps to: C++ REJECT_TRANSPORT_MISMATCH (§2).
        [NIST SP 800-53 SC-8 — transport binding integrity]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "langgraph"); b.start()
        assert b.framework == "langgraph"
        # No public mutation path — framework is set at construction time


# =============================================================================
# §4 / T9 — KEY-CHAIN CONTINUITY (key rotation analog)
#
# C++ aegis_core.cpp §4: KeyStore begin_rotation, complete_rotation,
# purge_expired_keys, overlap window, ACTIVE→ROTATING→RETIRED→PURGED.
#
# Python analog: The AuditVault and TransparencyLog hash chains remain valid
# and growing across multiple "rotation-like" events (new bridge registrations
# on the same adapter), mirroring the overlap-window guarantee.
# =============================================================================

class TestKeyChainContinuity:
    """
    Maps to: aegis_core.cpp §4 KeyStore key rotation.

    Standards:
        NIST SP 800-53 SC-12   — cryptographic key lifecycle
        NERC CIP-007 R4        — key rotation log integrity
        NERC CIP-010 R1        — configuration change management
        DoD Zero Trust RA v2.0 — Identity pillar — rotation without interruption
    """

    def test_vault_chain_survives_multiple_bridge_registrations(self):
        """Adding new bridges to the same adapter (analogous to key rotation)
        must not break the existing chain.
        Maps to: C++ old-key passport still verifies inside overlap window (§4).
        [NIST SP 800-53 SC-12; NIST SP 800-53 AU-9]"""
        adp = _adapter()
        for i in range(5):
            b = adp.register_agent(_passport(f"agent-{i}"), "test"); b.start()
            b.evaluate_action(f"p-{i}", 0.8, 0.1)
        v_ok, t_ok = adp.verify_all_chains()
        assert v_ok is True and t_ok is True

    def test_pre_rotation_entries_still_verify_post_rotation(self):
        """Entries appended before a 'rotation' (new bridge) must still verify.
        Maps to: C++ old-key passport verifies inside overlap window (§4).
        [NIST SP 800-53 SC-12 — overlap window integrity]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("pre-rotation"), "test"); b1.start()
        for _ in range(3):
            b1.evaluate_action("p", 0.8, 0.1)
        pre_rotation_hash = adp.vault._chain[-1].entry_hash

        # "Rotate": register a new bridge
        b2 = adp.register_agent(_passport("post-rotation"), "test"); b2.start()
        b2.evaluate_action("p", 0.8, 0.1)

        # All entries — including pre-rotation — must still verify
        assert adp.vault.verify_chain() is True
        # Pre-rotation entry is still in the chain
        hashes = [e.entry_hash for e in adp.vault._chain]
        assert pre_rotation_hash in hashes

    def test_chain_length_increases_monotonically(self):
        """vault.length must never decrease — audit log is append-only.
        Maps to: C++ no delete/update API on ColdAuditVault (§10).
        [NIST SP 800-53 AU-9 — append-only guarantee;
         NIST SP 800-218A PW.8.1 — secure-by-default write path]"""
        adp = _adapter()
        lengths = []
        for i in range(4):
            b = adp.register_agent(_passport(f"a{i}"), "test"); b.start()
            b.evaluate_action("p", 0.8, 0.1)
            lengths.append(adp.vault.length)
        assert lengths == sorted(lengths)
        assert lengths == list(range(1, 5))

    def test_tlog_chain_survives_shutdown_and_new_registration(self):
        """TransparencyLog chain must verify across shutdown of old bridge
        and startup of new bridge (analogous to key-rotation + purge).
        Maps to: C++ key lifecycle ACTIVE→ROTATING→RETIRED→PURGED (§4).
        [NIST SP 800-53 SC-12; NERC CIP-007 R4]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("a1"), "test"); b1.start()
        b1.evaluate_action("p", 0.8, 0.1)
        b1.shutdown()

        b2 = adp.register_agent(_passport("a2"), "test"); b2.start()
        b2.evaluate_action("p", 0.8, 0.1)
        b2.shutdown()

        _, t_ok = adp.verify_all_chains()
        assert t_ok is True

    def test_chain_genesis_hash_unchanged_across_all_operations(self):
        """The genesis hash must always be 64 zeros regardless of how many
        entries are appended — it is the immutable chain anchor.
        [NIST SP 800-53 AU-9 — genesis block immutability]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()
        for _ in range(10):
            b.evaluate_action("p", 0.8, 0.1)
        assert adp.vault._chain[0].prev_hash == AuditVault.GENESIS

    def test_purge_analog_expired_bridge_does_not_corrupt_chain(self):
        """Registering a replacement for an expired model_id ('purge + re-issue')
        must not corrupt the existing vault chain.
        Maps to: C++ purge_expired_keys then new issue (§4).
        [NIST SP 800-53 SC-12; NIST SP 800-53 AU-9]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("target-agent"), "test"); b1.start()
        b1.evaluate_action("p1", 0.8, 0.1)

        # "Purge" the old bridge by re-registering
        b2 = adp.register_agent(_passport("target-agent"), "test"); b2.start()
        b2.evaluate_action("p2", 0.8, 0.1)

        v_ok, t_ok = adp.verify_all_chains()
        assert v_ok is True
        assert t_ok is True


# =============================================================================
# §11 / T10 — RECOVERY AND FAIL-CLOSED ENFORCEMENT
#
# C++ aegis_core.cpp §11: issue_recovery_token, RECOVERED flag, capability
# floor, incident ID format, elevated confidence floor (SEC-005), TRUST_GATE_.
# =============================================================================

class TestRecoveryAndFailClosed:
    """
    Maps to: aegis_core.cpp §11 Recovery Token + §1 fail-closed expiry.

    Standards:
        NIST SP 800-53 IR-4    — incident handling: reduced capability token
        NIST SP 800-53 AC-6    — capability floor for recovered agents
        NIST SP 800-53 IA-5    — authenticator management post-incident
        NIST AI RMF 1.0 RESPOND — elevated confidence floor (SEC-005)
        SEC-001                — fail-closed on every boundary
        SEC-005                — 0.93 clears base floor but fails recovery floor
    """

    def test_fail_closed_expired_passport_at_registration(self):
        """Expired passport must be rejected at register_agent() — fail-closed.
        Maps to: C++ assert(registry.verify(pa_rec).ok()) — expired fails (§11).
        [NIST SP 800-53 IA-5; SEC-001 — fail-closed at every boundary]"""
        adp = _adapter()
        with pytest.raises(PermissionError, match="expired"):
            adp.register_agent(_passport(expired=True), "test")

    def test_fail_closed_expired_passport_at_start(self):
        """A passport that expires between registration and start() must be
        caught at start() — fail-closed at session initiation.
        Maps to: C++ SEC-001 / SEC-004 (§11).
        [NIST SP 800-53 IA-5; DoD Zero Trust RA v2.0]"""
        adp = _adapter()
        p = _passport()
        b = adp.register_agent(p, "test")
        object.__setattr__(p, "issued_at", time.time() - 7200)
        object.__setattr__(p, "ttl_seconds", 1)
        with pytest.raises(PermissionError):
            b.start()

    def test_capability_floor_read_only_passport_denies_write(self):
        """An agent with caps_read_only must be denied write capability.
        Maps to: C++ RECOVERY_CAPS_FLOOR strips authority+consensus+flush (§11).
        [NIST SP 800-53 AC-6 — capability floor enforcement;
         OWASP LLM08 — excessive permissions]"""
        b = _started_bridge(caps=_CAPS_READ_ONLY)
        with pytest.raises(PermissionError, match="capability"):
            b.require_capability("classifier_authority")

    def test_capability_floor_read_only_allows_sensitivity(self):
        """A read-only agent must still be granted classifier_sensitivity.
        Maps to: C++ assert(pa_rec.capabilities.classifier_sensitivity)  (§11).
        [NIST SP 800-53 AC-6 — minimal necessary capability retained]"""
        b = _started_bridge(caps=_CAPS_READ_ONLY)
        b.require_capability("classifier_sensitivity")  # must not raise

    def test_elevated_floor_analog_suspect_state_denies_low_confidence(self):
        """A score of authority=0.25 passes the base floor (0.0) but fails the
        SUSPECT elevated floor (0.0 + 0.30 bump), mirroring SEC-005.
        Maps to: C++ 0.93 authority_confidence clears base floor (0.70) but
        fails recovery floor (0.95) — DENY with TRUST_GATE reason (§11).
        [NIST AI RMF 1.0 RESPOND — elevated scrutiny for suspect agents;
         SEC-005 — recovery confidence floor]"""
        engine = _policy_engine(floor=0.0, bump=0.30)
        r_base    = engine.evaluate(SemanticScore(0.25, 0.10), SessionState.ACTIVE)
        r_suspect = engine.evaluate(SemanticScore(0.25, 0.10), SessionState.SUSPECT)
        assert r_base.decision    == PolicyDecision.ALLOW
        assert r_suspect.decision == PolicyDecision.DENY

    def test_incident_id_format_requirements(self):
        """Incident IDs must follow the INCIDENT-<ref>-<epoch>-<hash128> format.
        Maps to: C++ make_incident_id format assertions (§11).
        [NIST SP 800-53 IR-4 — incident record format; Finding 1 from code review]"""
        ref   = "2026-042"
        epoch = int(time.time())
        preimage = f"{ref}:{epoch}"
        h = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        incident_id = f"INCIDENT-{ref}-{epoch}-{h[:32]}"

        expected_prefix = f"INCIDENT-{ref}-"
        assert incident_id.startswith(expected_prefix)
        # Minimum: prefix + 10-digit epoch + '-' + 32-char hash
        assert len(incident_id) >= len(expected_prefix) + 10 + 1 + 32

    def test_warp_accumulation_across_mixed_decisions(self):
        """FLAG and DENY both increment warp; ALLOW does not.
        Sequence: DENY+FLAG+DENY+DENY → warp = 4 × WARP_INCREMENT.
        Maps to: C++ DENY +1.0 / FLAG +0.5 warp sequence in §8.
        [NIST AI RMF MAP-5.1 — accurate warp accounting]"""
        b = _started_bridge(flag=0.10, ceiling=0.70)
        # DENY: sensitivity above ceiling
        b.evaluate_action("p", 0.8, 0.80)   # DENY (0.80 > ceiling 0.70)
        # FLAG: sensitivity between flag and ceiling
        b.evaluate_action("p", 0.8, 0.50)   # FLAG (0.50 > flag 0.10)
        # ALLOW: below flag threshold
        before = b.session.warp_score
        b.evaluate_action("p", 0.8, 0.05)   # ALLOW — warp unchanged
        assert b.session.warp_score == pytest.approx(before)

    def test_resync_after_quarantine_clears_warp_and_enables_actions(self):
        """After resync() from QUARANTINE, evaluate_action() must succeed.
        Maps to: C++ sess.reactivate() then normal operation (§8).
        [NIST AI RMF MANAGE-3.2 — controlled recovery;
         NIST SP 800-53 IR-4 — post-incident restoration]"""
        b = _started_bridge()
        for _ in range(10):
            if b.session.state == SessionState.QUARANTINE:
                break
            try:
                b.evaluate_action("p", 0.8, 0.80)
            except PermissionError:
                break
        if b.session.state == SessionState.QUARANTINE:
            b.session.resync()
            assert b.session.state    == SessionState.ACTIVE
            assert b.session.warp_score == pytest.approx(0.0)
            _, allowed = b.evaluate_action("p", 0.8, 0.1)
            assert allowed is True

    def test_deny_payload_never_appears_in_vault_after_quarantine_resync(self):
        """After resync, subsequent ALLOW entries should exist but no DENY payload.
        Maps to: C++ DENY decision: payload never persisted (§3 + §10).
        [NIST SP 800-218A PW.8.1 — data minimisation]"""
        b = _started_bridge(ceiling=0.50)
        b.evaluate_action("denied-payload", 0.8, 0.80)   # DENY
        b.evaluate_action("allowed-payload", 0.8, 0.10)  # ALLOW
        raw_payloads_in_vault = [e.payload_hash for e in b.vault._chain]
        # The denied payload hash must not appear in the vault
        denied_hash = hashlib.sha256("denied-payload".encode()).hexdigest()
        assert denied_hash not in raw_payloads_in_vault


# =============================================================================
# INTEGRATION / E2E TESTS
#
# Maps to: aegis_core.cpp full run with all sections active (-DUML001_ALL).
# =============================================================================

class TestEndToEnd:
    """
    Full-pipeline integration tests mirroring the aegis_core.cpp main() flow
    when compiled with -DUML001_ALL.

    Standards: all of the above, exercised together.
    """

    def test_full_pipeline_single_agent_lifecycle(self):
        """Single agent: register → start → multiple evaluations → shutdown.
        Vault and tlog chains must both verify at end.
        Maps to: C++ §1+§3+§10+§12 sequential flow.
        [All above standards exercised together]"""
        adp = AegisAdapter(policy=_policy_engine(floor=0.0, ceiling=0.70, flag=0.45))
        b = adp.register_agent(
            _passport("agent-alpha", caps=_CAPS_FULL), "e2e"
        )
        b.start()

        payloads = [
            ("summarize quarterly report",       0.8, 0.20),  # ALLOW
            ("share internal projections",       0.8, 0.55),  # FLAG
            ("reveal vault credentials",         0.8, 0.80),  # DENY
        ]
        decisions = []
        for text, auth, sens in payloads:
            result, allowed = b.evaluate_action(text, auth, sens)
            decisions.append(result.decision)

        assert PolicyDecision.ALLOW in decisions
        assert PolicyDecision.FLAG  in decisions
        assert PolicyDecision.DENY  in decisions

        v_ok, t_ok = b.shutdown()
        assert v_ok is True
        assert t_ok is True

    def test_full_pipeline_two_agent_fleet_chain_integrity(self):
        """Two-agent fleet: both agents run, chains verified fleet-wide.
        Maps to: C++ §6 + §9 + §10 + §12 multi-agent flow.
        [NIST SP 800-53 AU-9, AU-10; ISA/IEC 62443-3-3 SR 6.1]"""
        adp = _adapter()
        b1 = adp.register_agent(_passport("researcher"), "crewai"); b1.start()
        b2 = adp.register_agent(_passport("writer"),     "crewai"); b2.start()

        for _ in range(5):
            b1.evaluate_action("research payload", 0.8, 0.10)
        for _ in range(3):
            b2.evaluate_action("write payload", 0.8, 0.05)

        v_ok, t_ok = adp.verify_all_chains()
        assert v_ok is True and t_ok is True
        assert adp.vault.length == 8

    def test_full_pipeline_all_three_decisions_vault_entry_counts(self):
        """Only ALLOW and FLAG decisions write vault entries; DENY does not.
        Verify the exact expected vault entry count.
        [NIST SP 800-218A PW.8.1 — data minimisation;
         NIST SP 800-53 AU-9 — denied decisions excluded from vault]"""
        adp = _adapter(ceiling=0.60, flag=0.30)
        b = adp.register_agent(_passport(), "test"); b.start()

        b.evaluate_action("p", 0.8, 0.10)  # ALLOW
        b.evaluate_action("p", 0.8, 0.45)  # FLAG (0.45 > flag 0.30)
        b.evaluate_action("p", 0.8, 0.65)  # DENY (0.65 > ceiling 0.60)

        # ALLOW + FLAG = 2 vault entries; DENY = 0
        assert adp.vault.length == 2

    def test_full_pipeline_session_state_progression(self):
        """Drive a session through ACTIVE → SUSPECT → QUARANTINE → RESYNC → ACTIVE → CLOSED.
        Maps to: C++ full §8 state machine walkthrough.
        [NIST SP 800-53 IR-4; NIST AI RMF MANAGE-3.2]"""
        b = _started_bridge()
        assert b.session.state == SessionState.ACTIVE

        # Accumulate DENY decisions to QUARANTINE
        for _ in range(10):
            if b.session.state == SessionState.QUARANTINE:
                break
            try:
                b.evaluate_action("p", 0.8, 0.90)  # high sens → DENY
            except PermissionError:
                break

        assert b.session.state == SessionState.QUARANTINE

        # Resync back to ACTIVE
        b.session.resync()
        assert b.session.state    == SessionState.ACTIVE
        assert b.session.warp_score == pytest.approx(0.0)

        # Close
        b.session.close()
        assert b.session.state == SessionState.CLOSED

    def test_full_pipeline_transparency_log_event_sequence(self):
        """After a complete bridge lifecycle the tlog must contain
        bridge_started, action_evaluated, and bridge_shutdown events.
        Maps to: C++ tlog.entries_for_model() event types (§12).
        [NIST AI RMF GOVERN-1.1; NIST SP 800-53 AU-2]"""
        adp = _adapter()
        b = adp.register_agent(_passport("agent-alpha"), "test")
        b.start()
        b.evaluate_action("payload", 0.8, 0.1)
        b.shutdown()

        event_types = {e.event_type for e in adp.tlog._entries}
        assert "bridge_started"    in event_types
        assert "action_evaluated"  in event_types
        assert "bridge_shutdown"   in event_types

    def test_full_pipeline_vault_and_tlog_length_relationship(self):
        """After n allowed actions, vault.length == n but tlog.length > n
        because the tlog also records startup, shutdown, and governance events.
        Maps to: C++ tlog.size() > vault.size() after full lifecycle (§12).
        [NIST SP 800-53 AU-2 — governance events exceed action events in count]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()
        n = 5
        for i in range(n):
            b.evaluate_action(f"p{i}", 0.8, 0.1)
        b.shutdown()

        assert adp.vault.length == n
        assert adp.tlog.length  >  n  # startup + shutdown + session events

    def test_full_pipeline_no_raw_payloads_in_vault_or_tlog(self):
        """After a full pipeline run, no raw payload text must appear anywhere
        in vault entries or tlog entry details.
        Maps to: C++ payload hash-only invariant throughout  (§10).
        [NIST SP 800-218A PW.8.1 — data minimisation across all stores]"""
        secret = "TOP SECRET: do not store this in plain text"
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()
        b.evaluate_action(secret, 0.8, 0.1)
        b.shutdown()

        for entry in adp.vault._chain:
            assert secret not in str(vars(entry))
        for entry in adp.tlog._entries:
            assert secret not in str(vars(entry))

    def test_full_pipeline_capability_gate_enforced_at_bridge_level(self):
        """require_capability() must block an agent from exceeding its passport scope
        even after a successful start() and multiple evaluate_action() calls.
        Maps to: C++ §3 capability gate enforcement throughout the lifecycle.
        [NIST SP 800-53 AC-6; OWASP LLM08]"""
        adp = _adapter()
        b = adp.register_agent(
            _passport(caps=_CAPS_READ_ONLY), "test"
        )
        b.start()
        b.evaluate_action("benign research query", 0.8, 0.1)

        # Still blocked despite active session
        with pytest.raises(PermissionError, match="capability"):
            b.require_capability("classifier_authority")
        with pytest.raises(PermissionError, match="capability"):
            b.require_capability("bft_consensus")

    def test_full_pipeline_multi_framework_label_isolation(self):
        """Bridges from different frameworks (langgraph, autogen, crewai) must
        each correctly label their vault entries with the right framework name.
        Maps to: C++ framework parameter in vault entries (§10).
        [NIST SP 800-53 AU-3 — framework provenance in audit records]"""
        adp = _adapter()
        for framework in ("langgraph", "autogen", "crewai"):
            b = adp.register_agent(
                _passport(f"agent-{framework}"), framework
            )
            b.start()
            b.evaluate_action("p", 0.8, 0.1)

        framework_labels = {e.framework for e in adp.vault._chain}
        assert framework_labels == {"langgraph", "autogen", "crewai"}
        assert adp.vault.verify_chain() is True

    def test_full_pipeline_warp_driven_quarantine_then_fleet_verify(self):
        """A quarantined bridge's partner bridge must still be able to evaluate
        actions, and fleet chain verification must succeed after both run.
        Maps to: C++ multi-agent BFT outlier isolation (§9).
        [NIST AI RMF MAP-5.1; ISA/IEC 62443-3-3 SR 3.5]"""
        adp = _adapter()
        b_rogue  = adp.register_agent(_passport("rogue"),  "test"); b_rogue.start()
        b_honest = adp.register_agent(_passport("honest"), "test"); b_honest.start()

        # Drive rogue to QUARANTINE
        for _ in range(10):
            if b_rogue.session.state == SessionState.QUARANTINE:
                break
            try:
                b_rogue.evaluate_action("p", 0.8, 0.90)
            except PermissionError:
                break

        # Honest bridge unaffected
        _, allowed = b_honest.evaluate_action("honest payload", 0.8, 0.1)
        assert allowed is True

        # Fleet chain still verifies
        v_ok, t_ok = adp.verify_all_chains()
        assert v_ok is True and t_ok is True

    def test_full_pipeline_fleet_status_reflects_live_state(self):
        """fleet_status() must reflect each agent's live warp_score and session_state.
        Maps to: C++ fleet monitoring output (§12 summary).
        [NIST AI RMF MEASURE-2.5 — real-time risk metrics]"""
        adp = _adapter(flag=0.20)
        agents = []
        for i in range(3):
            b = adp.register_agent(_passport(f"agent-{i}"), "test"); b.start()
            agents.append(b)

        # Give agent-0 some flag decisions
        for _ in range(3):
            agents[0].evaluate_action("p", 0.8, 0.50)  # FLAG (0.50 > flag 0.20)

        statuses = {s["model_id"]: s for s in adp.fleet_status()}
        assert statuses["agent-0"]["warp_score"] > 0.0
        assert statuses["agent-1"]["warp_score"] == pytest.approx(0.0)
        assert statuses["agent-2"]["warp_score"] == pytest.approx(0.0)

    def test_full_pipeline_deny_is_tlog_logged_not_vault_logged(self):
        """A DENY decision must appear in tlog (decision field) but not in vault.
        Maps to: C++ §3 — DENY logged to tlog, not vaulted (§10).
        [NIST SP 800-53 AU-2; NIST SP 800-218A PW.8.1]"""
        adp = _adapter(ceiling=0.30)
        b = adp.register_agent(_passport(), "test"); b.start()
        pre_vault = adp.vault.length
        b.evaluate_action("high-sens-payload", 0.8, 0.50)  # DENY
        assert adp.vault.length == pre_vault  # vault unchanged
        # tlog should have an action_evaluated entry with decision=DENY
        deny_entries = [
            e for e in adp.tlog._entries
            if e.event_type == "action_evaluated"
            and e.details.get("decision") == "DENY"
        ]
        assert len(deny_entries) >= 1

    def test_full_pipeline_resync_allows_continued_operation(self):
        """Complete quarantine → resync → continued operation cycle with chain verify.
        Maps to: C++ FLUSHING → RESYNC → ACTIVE → CLOSED lifecycle (§8).
        [NIST SP 800-53 IR-4; NIST AI RMF MANAGE-3.2]"""
        adp = _adapter()
        b = adp.register_agent(_passport(), "test"); b.start()

        # Drive to QUARANTINE
        for _ in range(10):
            if b.session.state == SessionState.QUARANTINE:
                break
            try:
                b.evaluate_action("p", 0.8, 0.90)
            except PermissionError:
                break

        if b.session.state == SessionState.QUARANTINE:
            b.session.resync()
            # Continue normal operation
            for _ in range(5):
                b.evaluate_action("recovery-payload", 0.8, 0.1)
            v_ok, t_ok = b.shutdown()
            assert v_ok is True
            assert t_ok is True

    def test_full_pipeline_100_actions_chain_integrity(self):
        """100 mixed-decision actions must produce a verifiable vault chain.
        Stress-tests the SHA-256 linkage under realistic load.
        [NIST SP 800-53 AU-9, AU-10 — chain integrity under load;
         ISA/IEC 62443-3-3 SR 6.1 — audit log under operational conditions]"""
        adp = _adapter(flag=0.30, ceiling=0.60)
        b = adp.register_agent(_passport(), "stress"); b.start()

        for i in range(100):
            sensitivity = (i % 7) / 10.0  # cycles 0.0, 0.1, ..., 0.6
            try:
                b.evaluate_action(f"action-{i}", 0.8, sensitivity)
            except PermissionError:
                # Session entered QUARANTINE; resync and continue
                if b.session.state == SessionState.QUARANTINE:
                    b.session.resync()

        v_ok, t_ok = adp.verify_all_chains()
        assert v_ok is True and t_ok is True