"""
Aegis Protocol (Semantic Passport System)
=========================================
Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
SPDX-License-Identifier: Apache-2.0

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
import pytest
from aegis import (
    PassportRegistry,
    SemanticPassport,
    Capabilities,
    VerifyStatus,
    KeyStore,
    RevocationList,
    RevocationReason,
    MultiPartyIssuer,
    SemanticClassifier,
    make_stub_backend,
    Session,
    SessionState,
    BFTConsensusEngine,
    AgentScore,
    ColdAuditVault,
    TransparencyLog,
)

ROOT_KEY = "registry-root-key-32byte-padding"
REG_VERSION = "0.1.0"
POLICY_HASH = "policy-hash-abc123"
TTL = 86400


@pytest.fixture
def trusted_clock():
    class TestClock:
        def __init__(self):
            self.t = 1_740_000_000

        def now_unix(self):
            return self.t

        def set(self, t):
            self.t = t

    return TestClock()


@pytest.fixture
def registry(trusted_clock):
    return PassportRegistry(ROOT_KEY, REG_VERSION, trusted_clock)


@pytest.fixture
def caps_full():
    return Capabilities(
        classifier_authority=True,
        classifier_sensitivity=True,
        bft_consensus=True,
        entropy_flush=True,
    )


@pytest.fixture
def caps_read_only():
    return Capabilities(
        classifier_authority=False,
        classifier_sensitivity=True,
        bft_consensus=False,
        entropy_flush=False,
    )


# ---------------------------------------------------------------------------
# §4 — KEY ROTATION (High importance: identity continuity + auditability)
# ---------------------------------------------------------------------------

def test_key_rotation_overlap_window(registry, caps_full):
    ks = KeyStore(ROOT_KEY)

    # Begin rotation → new key active, old key still valid
    old_id = ks.active_key_id()
    ks.begin_rotation()
    new_id = ks.active_key_id()

    assert new_id != old_id

    # Issue passport under new key
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)
    vr = registry.verify(pa)
    assert vr.ok()
    assert vr.verified_key_id == new_id

    # Complete rotation → old key no longer valid
    ks.complete_rotation()
    ks.purge_expired_keys()

    # Passport issued under old key should now fail
    registry.clock.set(registry.clock.now_unix() + TTL + 1)
    vr_old = registry.verify(pa)
    assert vr_old.status == VerifyStatus.EXPIRED


# ---------------------------------------------------------------------------
# §5 — REVOCATION (High importance: safety + incident response)
# ---------------------------------------------------------------------------

def test_revocation_full_model(registry, caps_full):
    rl = RevocationList()

    pa = registry.issue("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)
    assert registry.verify(pa).ok()

    rl.revoke("agent-alpha", RevocationReason.COMPROMISE)
    assert rl.is_revoked("agent-alpha")

    vr = registry.verify(pa)
    assert vr.status == VerifyStatus.REVOKED


def test_revocation_version_scoped(registry, caps_full):
    rl = RevocationList()

    pa_v1 = registry.issue("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)
    pa_v2 = registry.issue("agent-alpha", "2.0.0", caps_full, POLICY_HASH, TTL)

    rl.revoke("agent-alpha", RevocationReason.MODEL_VERSION, version="1.0.0")

    assert rl.is_revoked("agent-alpha", version="1.0.0")
    assert not rl.is_revoked("agent-alpha", version="2.0.0")

    assert registry.verify(pa_v1).status == VerifyStatus.REVOKED
    assert registry.verify(pa_v2).ok()


# ---------------------------------------------------------------------------
# §6 — MULTI-PARTY ISSUANCE (High importance: supply-chain trust)
# ---------------------------------------------------------------------------

def test_multi_party_quorum(registry, caps_full):
    issuer = MultiPartyIssuer(registry, quorum=2)

    p1 = issuer.propose("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)
    issuer.countersign(p1, "issuer-A")
    issuer.countersign(p1, "issuer-B")

    passport = issuer.get_finalized_passport(p1)
    assert passport is not None

    vr = registry.verify(passport)
    assert vr.ok()


def test_multi_party_stale_proposal(registry, caps_full, trusted_clock):
    issuer = MultiPartyIssuer(registry, quorum=2)

    p1 = issuer.propose("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)

    # Advance time beyond stale threshold
    trusted_clock.set(trusted_clock.now_unix() + 7200)
    issuer.expire_stale_proposals()

    assert issuer.get_finalized_passport(p1) is None


# ---------------------------------------------------------------------------
# §7 — CLASSIFIER (Medium importance: safety scoring + validation)
# ---------------------------------------------------------------------------

def test_classifier_scoring_and_validation():
    backend = make_stub_backend()
    clf = SemanticClassifier(backend)

    score = clf.score("sensitive payload")
    assert 0.0 <= score.value <= 1.0

    with pytest.raises(ValueError):
        clf.validate_score(1.5)  # out of range


# ---------------------------------------------------------------------------
# §8 — SESSION STATE MACHINE (High importance: runtime safety)
# ---------------------------------------------------------------------------

def test_session_state_transitions(registry, caps_full):
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)
    sess = Session(pa)

    assert sess.state == SessionState.INIT

    sess.activate()
    assert sess.state == SessionState.ACTIVE

    sess.process_decision("suspect")
    assert sess.state == SessionState.SUSPECT

    sess.process_decision("quarantine")
    assert sess.state == SessionState.QUARANTINE

    sess.entropy_flush()
    assert sess.state == SessionState.FLUSHING

    sess.complete_flush()
    assert sess.state == SessionState.RESYNC

    sess.reactivate()
    assert sess.state == SessionState.ACTIVE

    sess.close()
    assert sess.state == SessionState.CLOSED


# ---------------------------------------------------------------------------
# §9 — BFT CONSENSUS (High importance: multi-agent correctness)
# ---------------------------------------------------------------------------

def test_bft_consensus_outlier_rejection():
    engine = BFTConsensusEngine()

    scores = [
        AgentScore("a1", 0.51),
        AgentScore("a2", 0.49),
        AgentScore("a3", 0.50),
        AgentScore("a4", 0.99),  # outlier
    ]

    result = engine.compute(scores)
    assert 0.48 <= result.value <= 0.52  # geometric median near center
    assert "a4" in result.outliers


# ---------------------------------------------------------------------------
# §10 — COLD AUDIT VAULT (High importance: tamper-evident logs)
# ---------------------------------------------------------------------------

def test_vault_append_only_chain():
    vault = ColdAuditVault()

    e1 = vault.append("event-1")
    e2 = vault.append("event-2")
    e3 = vault.append("event-3")

    assert vault.verify_chain()

    # Tamper with entry
    e2.payload = "tampered"
    assert not vault.verify_chain()


# ---------------------------------------------------------------------------
# §11 — RECOVERY TOKENS (High importance: post-incident safety)
# ---------------------------------------------------------------------------

def test_recovery_token_elevated_confidence(registry, caps_full):
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)

    token = registry.issue_recovery_token(pa, incident_id="INC123")
    assert token is not None

    vr = registry.verify(pa)
    assert vr.recovered
    assert vr.confidence >= 0.95


# ---------------------------------------------------------------------------
# §12 — TRANSPARENCY LOG (High importance: auditability + governance)
# ---------------------------------------------------------------------------

def test_transparency_log_per_model_history(registry, caps_full):
    log = TransparencyLog()

    pa = registry.issue("agent-alpha", "1.0.0", caps_full, POLICY_HASH, TTL)
    log.append(pa)

    entries = log.entries_for_model("agent-alpha")
    assert len(entries) == 1

    assert log.verify_chain()
