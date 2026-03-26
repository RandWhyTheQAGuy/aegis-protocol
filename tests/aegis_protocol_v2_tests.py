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
import uuid
import pytest


# =============================================================================
# STUBS — CLOCK
# =============================================================================

class StubClock:
    def __init__(self):
        self.t = 0

    def now_unix(self):
        return self.t

    def set(self, t):
        self.t = t

    def advance(self, dt):
        self.t += dt


class StubBftClockClient:
    def __init__(self, clock):
        self.clock = clock

    def now_unix(self):
        return self.clock.now_unix()

    def last_uncertainty_s(self):
        return 0

    def last_issued_at(self):
        return self.clock.now_unix()


# =============================================================================
# STUBS — VAULT
# =============================================================================

class StubVault:
    def __init__(self):
        self.entries = []

    def append(self, *args, **kwargs):
        self.entries.append((args, kwargs))


# =============================================================================
# STUBS — PASSPORT REGISTRY
# =============================================================================

class Capabilities:
    def __init__(self, classifier_authority, classifier_sensitivity, bft_consensus, entropy_flush):
        self.classifier_authority = classifier_authority
        self.classifier_sensitivity = classifier_sensitivity
        self.bft_consensus = bft_consensus
        self.entropy_flush = entropy_flush


class VerifyResult:
    def __init__(self, status, recovered=False):
        self.status = status
        self.recovered = recovered

    def ok(self):
        return self.status == "OK"


class StubPassport:
    def __init__(self, model_id, version, caps, policy, issued_at, ttl):
        self.model_id = model_id
        self.version = version
        self.caps = caps
        self.policy = policy
        self.issued_at = issued_at
        self.ttl = ttl


class StubPassportRegistry:
    def __init__(self, clock):
        self.clock = clock
        self.revoked = set()

    def issue(self, model_id, version, caps, policy, ttl):
        return StubPassport(model_id, version, caps, policy, self.clock.now_unix(), ttl)

    def verify(self, passport):
        now = self.clock.now_unix()
        if passport.model_id in self.revoked:
            return VerifyResult("REVOKED")
        if now > passport.issued_at + passport.ttl:
            return VerifyResult("EXPIRED")
        return VerifyResult("OK")

    def apply_revocation_list(self, rl):
        self.revoked |= rl.revoked


# =============================================================================
# STUBS — POLICY ENGINE
# =============================================================================

class PolicyDecision:
    ALLOW = "ALLOW"
    DENY = "DENY"


class StubPolicyEngine:
    def __init__(self, default):
        self.default = default
        self.rules = {}

    def allow(self, model_id, action):
        self.rules[(model_id, action)] = PolicyDecision.ALLOW

    def evaluate(self, passport, action):
        return self.rules.get((passport.model_id, action), self.default)


# =============================================================================
# STUBS — SESSION
# =============================================================================

from enum import Enum, auto

class SessionState(Enum):
    INIT = auto()
    ACTIVE = auto()
    SUSPECT = auto()
    QUARANTINE = auto()
    FLUSHING = auto()
    RESYNC = auto()
    CLOSED = auto()


class StubSessionConfig:
    def __init__(self, allow, flag, deny, suspect_thresh, quarantine_thresh):
        self.allow = allow
        self.flag = flag
        self.deny = deny
        self.suspect_thresh = suspect_thresh
        self.quarantine_thresh = quarantine_thresh


class StubSession:
    def __init__(self, sid, model_id, cfg, vault):
        self.sid = sid
        self.model_id = model_id
        self.cfg = cfg
        self.vault = vault
        self.state = SessionState.INIT
        self.score = 0

    def activate(self):
        self.state = SessionState.ACTIVE

    def apply_policy(self, action):
        if action == "FLAG":
            self.score += self.cfg.flag
        elif action == "DENY":
            self.score += self.cfg.deny

        if self.score >= self.cfg.quarantine_thresh:
            self.state = SessionState.QUARANTINE
        elif self.score >= self.cfg.suspect_thresh:
            self.state = SessionState.SUSPECT

    def flush(self):
        self.state = SessionState.FLUSHING

    def complete_flush(self):
        self.state = SessionState.RESYNC

    def reactivate(self):
        self.state = SessionState.ACTIVE


# =============================================================================
# STUBS — HANDSHAKE
# =============================================================================

class StubHandshakeContext:
    def __init__(self):
        self.session_id = "sess-" + uuid.uuid4().hex
        self.forward_secrecy = True


class StubHandshakeValidator:
    def __init__(self, passport):
        self.passport = passport

    def build_hello(self):
        return {"nonce": uuid.uuid4().hex}

    def handle_hello(self, hello):
        return {"nonce": hello["nonce"]}

    def handle_challenge(self, challenge):
        return {"nonce": challenge["nonce"]}

    def handle_confirm(self, confirm):
        return StubHandshakeContext()


# =============================================================================
# STUBS — MULTI-PARTY ISSUER
# =============================================================================

class StubMultiPartyIssuer:
    def __init__(self, registry, quorum):
        self.registry = registry
        self.quorum = quorum
        self.proposals = {}

    def propose(self, model_id, version, caps, policy, ttl):
        pid = f"{model_id}-{version}"
        self.proposals[pid] = {"votes": 0, "args": (model_id, version, caps, policy, ttl)}
        return pid

    def countersign(self, pid, signer):
        self.proposals[pid]["votes"] += 1

    def get_finalized_passport(self, pid):
        if self.proposals[pid]["votes"] >= self.quorum:
            m, v, c, p, t = self.proposals[pid]["args"]
            return self.registry.issue(m, v, c, p, t)
        return None


# =============================================================================
# STUBS — REVOCATION
# =============================================================================

class StubRevocationList:
    def __init__(self):
        self.revoked = set()

    def revoke(self, model_id):
        self.revoked.add(model_id)


# =============================================================================
# STUBS — KEY ROTATION
# =============================================================================

class StubKeyStore:
    def __init__(self):
        self.key = 1

    def active_key_id(self):
        return self.key

    def begin_rotation(self):
        self.key += 1


# =============================================================================
# STUBS — TRANSPARENCY LOG
# =============================================================================

class StubTransparencyLog:
    def __init__(self):
        self.entries = []

    def append(self, passport):
        self.entries.append(passport)

    def entries_for(self, model_id):
        return [p for p in self.entries if p.model_id == model_id]


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def clock():
    c = StubClock()
    c.set(1_740_000_000)
    return c

@pytest.fixture
def vault():
    return StubVault()

@pytest.fixture
def registry(clock):
    return StubPassportRegistry(clock)

@pytest.fixture
def caps_full():
    return Capabilities(True, True, True, True)

@pytest.fixture
def caps_auth_only():
    return Capabilities(True, False, False, False)

@pytest.fixture
def caps_flush_only():
    return Capabilities(False, False, False, True)


# =============================================================================
# TESTS
# =============================================================================

def test_bft_clock_client(clock):
    client = StubBftClockClient(clock)
    assert client.now_unix() == 1_740_000_000
    assert client.last_uncertainty_s() == 0
    assert client.last_issued_at() == 1_740_000_000


def test_passport_issue_and_verify(registry, caps_full, caps_auth_only, caps_flush_only):
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 86400)
    pb = registry.issue("agent-beta", "1.0.0", caps_auth_only, "policy", 86400)
    pc = registry.issue("agent-gamma", "1.0.0", caps_flush_only, "policy", 86400)

    assert registry.verify(pa).ok()
    assert registry.verify(pb).ok()
    assert registry.verify(pc).ok()


def test_passport_expiry(registry, caps_full, clock):
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 10)
    clock.advance(20)
    assert registry.verify(pa).status == "EXPIRED"


def test_policy_engine(registry, caps_full):
    engine = StubPolicyEngine(default=PolicyDecision.DENY)
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 86400)

    engine.allow("agent-alpha", "classify")
    assert engine.evaluate(pa, "classify") == PolicyDecision.ALLOW
    assert engine.evaluate(pa, "unknown") == PolicyDecision.DENY


def test_session_warp_score(vault):
    cfg = StubSessionConfig(-0.1, 0.5, 1.0, 1.0, 3.0)
    sess = StubSession("sess-alpha", "agent-alpha", cfg, vault)

    sess.activate()
    assert sess.state == SessionState.ACTIVE

    sess.apply_policy("FLAG")
    assert sess.state == SessionState.SUSPECT

    sess.apply_policy("DENY")
    assert sess.state == SessionState.QUARANTINE

    sess.flush()
    assert sess.state == SessionState.FLUSHING

    sess.complete_flush()
    assert sess.state == SessionState.RESYNC

    sess.reactivate()
    assert sess.state == SessionState.ACTIVE


def test_handshake(registry, caps_full):
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 86400)
    hv_init = StubHandshakeValidator(pa)
    hv_resp = StubHandshakeValidator(pa)

    hello = hv_init.build_hello()
    challenge = hv_resp.handle_hello(hello)
    confirm = hv_init.handle_challenge(challenge)
    ctx = hv_resp.handle_confirm(confirm)

    assert ctx is not None
    assert ctx.forward_secrecy
    assert ctx.session_id.startswith("sess-")


def test_multi_party_issuer(registry, caps_full):
    issuer = StubMultiPartyIssuer(registry, quorum=2)
    pid = issuer.propose("agent-alpha", "1.0.0", caps_full, "policy", 86400)
    issuer.countersign(pid, "op1")
    issuer.countersign(pid, "op2")

    passport = issuer.get_finalized_passport(pid)
    assert passport is not None
    assert registry.verify(passport).ok()


def test_revocation(registry, caps_full):
    rl = StubRevocationList()
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 86400)

    rl.revoke("agent-alpha")
    registry.apply_revocation_list(rl)

    assert registry.verify(pa).status == "REVOKED"


def test_key_rotation(registry, caps_full):
    ks = StubKeyStore()
    old = ks.active_key_id()
    ks.begin_rotation()
    new = ks.active_key_id()

    assert new != old

    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 86400)
    assert registry.verify(pa).ok()


def test_transparency_log(registry, caps_full):
    tlog = StubTransparencyLog()
    pa = registry.issue("agent-alpha", "1.0.0", caps_full, "policy", 86400)

    tlog.append(pa)
    entries = tlog.entries_for("agent-alpha")

    assert len(entries) == 1