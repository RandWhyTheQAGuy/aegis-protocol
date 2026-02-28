import hashlib
import hmac
import os
import time
import math
from typing import List, Dict, Optional, Tuple, Callable, Set, Any
from enum import Enum, auto
from dataclasses import dataclass, field

# =============================================================================
# 1. CRYPTO UTILS
# =============================================================================
def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def hmac_sha256_hex(key: str, data: str) -> str:
    key_bytes = key.encode('utf-8') if isinstance(key, str) else key
    return hmac.new(key_bytes, data.encode('utf-8'), hashlib.sha256).hexdigest()

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def generate_nonce(size: int = 32) -> str:
    return bytes_to_hex(os.urandom(size))

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 implemented with standard library hmac."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    for i in range(1, math.ceil(out_len / 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:out_len]

def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# =============================================================================
# 2. PASSPORT & CAPABILITIES
# =============================================================================
@dataclass
class Capabilities:
    classifier_authority: bool = False
    classifier_sensitivity: bool = False
    bft_consensus: bool = False
    entropy_flush: bool = False

class PassportFlag(Enum):
    RECOVERED = 1

@dataclass
class SemanticPassport:
    passport_version: str = "0.2"
    model_id: str = ""
    model_version: str = ""
    protocol: str = "UML-001"
    registry_version: str = ""
    capabilities: Capabilities = field(default_factory=Capabilities)
    policy_hash: str = ""
    issued_at: int = 0
    expires_at: int = 0
    recovery_token: str = ""
    signing_key_id: int = 0
    quorum_signed: bool = False
    signature: str = ""
    flags: int = 0

    def is_valid(self, now: int) -> bool:
        return bool(self.model_id and self.registry_version and 
                    self.issued_at <= now < self.expires_at)

    def is_recovered(self) -> bool:
        return bool(self.recovery_token) or bool(self.flags & PassportFlag.RECOVERED.value)

    def canonical_body(self) -> str:
        # Must match C++ std::ostringstream lexicographic exactly
        return (f"capabilities.bft_consensus={int(self.capabilities.bft_consensus)}"
                f"&capabilities.classifier_authority={int(self.capabilities.classifier_authority)}"
                f"&capabilities.classifier_sensitivity={int(self.capabilities.classifier_sensitivity)}"
                f"&capabilities.entropy_flush={int(self.capabilities.entropy_flush)}"
                f"&expires_at={self.expires_at}"
                f"&issued_at={self.issued_at}"
                f"&model_id={self.model_id}"
                f"&model_version={self.model_version}"
                f"&passport_version={self.passport_version}"
                f"&policy_hash={self.policy_hash}"
                f"&protocol={self.protocol}"
                f"&quorum_signed={int(self.quorum_signed)}"
                f"&recovery_token={self.recovery_token}"
                f"&registry_version={self.registry_version}")

    def sign(self, key: str):
        self.signature = hmac_sha256_hex(key, self.canonical_body())


# =============================================================================
# 3. TRANSPARENCY LOG
# =============================================================================
@dataclass
class TransparencyEntry:
    sequence_number: int = 0
    event_type: str = ""
    actor_id: str = ""
    subject_model_id: str = ""
    key_id_used: int = 0
    payload_summary: str = ""
    timestamp: int = 0
    prev_hash: str = ""
    entry_hash: str = ""

    def canonical(self) -> str:
        return (f"actor_id={self.actor_id}"
                f"&event_type={self.event_type}"
                f"&key_id_used={self.key_id_used}"
                f"&payload_summary={self.payload_summary}"
                f"&prev_hash={self.prev_hash}"
                f"&sequence_number={self.sequence_number}"
                f"&subject_model_id={self.subject_model_id}"
                f"&timestamp={self.timestamp}")

class TransparencyLog:
    def __init__(self):
        self.genesis_hash = "0" * 64
        self.entries: List[TransparencyEntry] = []
        self.by_model: Dict[str, List[int]] = {}

    def append(self, event_type: str, actor_id: str, subject_model_id: str,
               key_id_used: int, payload_summary: str, timestamp: int) -> int:
        e = TransparencyEntry(
            sequence_number=len(self.entries) + 1,
            event_type=event_type,
            actor_id=actor_id,
            subject_model_id=subject_model_id,
            key_id_used=key_id_used,
            payload_summary=payload_summary,
            timestamp=timestamp,
            prev_hash=self.entries[-1].entry_hash if self.entries else self.genesis_hash
        )
        e.entry_hash = sha256_hex(e.canonical())
        
        if subject_model_id:
            self.by_model.setdefault(subject_model_id, []).append(e.sequence_number)
            
        self.entries.append(e)
        return e.sequence_number

    def make_key_event_logger(self, registry_actor_id: str) -> Callable:
        def logger(event_type: str, key_id: int, timestamp: int, actor_id: str):
            summary = f"key_id={key_id} state={event_type}"
            self.append(event_type, actor_id or registry_actor_id, "", key_id, summary, timestamp)
        return logger

    def verify_chain(self) -> bool:
        expected_prev = self.genesis_hash
        for e in self.entries:
            if e.prev_hash != expected_prev: return False
            if e.entry_hash != sha256_hex(e.canonical()): return False
            expected_prev = e.entry_hash
        return True


# =============================================================================
# 4. KEY ROTATION
# =============================================================================
class KeyState(Enum):
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"
    RETIRED = "RETIRED"
    PURGED = "PURGED"

@dataclass
class KeyRecord:
    key_id: int = 0
    key_material: str = ""
    state: KeyState = KeyState.ACTIVE
    introduced_at: int = 0
    rotate_at: int = 0
    retire_at: int = 0
    purge_after: int = 0

    def is_usable_for_verify(self, now: int) -> bool:
        if self.state == KeyState.PURGED: return False
        if self.state == KeyState.RETIRED and self.purge_after > 0 and now > self.purge_after: return False
        return True

class KeyStore:
    def __init__(self, overlap_window_seconds: int = 3600, logger: Callable = None):
        self.overlap_window = overlap_window_seconds
        self.logger = logger
        self.keys: Dict[int, KeyRecord] = {}
        self.active_key_id = 0
        self.next_id = 1

    def _emit(self, event_type: str, key_id: int, ts: int, actor: str):
        if self.logger: self.logger(event_type, key_id, ts, actor)

    def introduce_key(self, key_material: str, now: int, actor_id: str = "system") -> int:
        if len(key_material) < 32: raise ValueError("Key material must be >= 32 bytes")
        new_id = self.next_id
        self.next_id += 1
        self.keys[new_id] = KeyRecord(key_id=new_id, key_material=key_material, introduced_at=now)
        self.active_key_id = new_id
        self._emit("KEY_INTRODUCED", new_id, now, actor_id)
        return new_id

    def begin_rotation(self, new_key_material: str, now: int, actor_id: str = "system") -> int:
        current = self.keys[self.active_key_id]
        current.state = KeyState.ROTATING
        current.rotate_at = now
        self._emit("KEY_ROTATING", current.key_id, now, actor_id)
        return self.introduce_key(new_key_material, now, actor_id)

    def complete_rotation(self, now: int, passport_max_ttl: int, actor_id: str = "system"):
        for k_id, rec in self.keys.items():
            if rec.state == KeyState.ROTATING and now >= rec.rotate_at + self.overlap_window:
                rec.state = KeyState.RETIRED
                rec.retire_at = now
                rec.purge_after = now + passport_max_ttl
                self._emit("KEY_RETIRED", k_id, now, actor_id)

    def signing_key(self) -> str:
        return self.keys[self.active_key_id].key_material

    def verify_with_any_valid_key(self, canonical_body: str, signature_hex: str, now: int) -> int:
        for k_id, rec in self.keys.items():
            if not rec.is_usable_for_verify(now): continue
            expected = hmac_sha256_hex(rec.key_material, canonical_body)
            if constant_eq(expected, signature_hex): return k_id
        return 0


# =============================================================================
# 5. REVOCATION
# =============================================================================
class RevocationReason(Enum):
    KEY_COMPROMISE = "KEY_COMPROMISE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    VERSION_SUPERSEDED = "VERSION_SUPERSEDED"
    OPERATOR_REQUEST = "OPERATOR_REQUEST"
    WARP_SCORE_THRESHOLD = "WARP_SCORE_THRESHOLD"

@dataclass
class RevocationRecord:
    model_id: str
    model_version: str
    revoking_actor: str
    reason: RevocationReason
    reason_detail: str
    revoked_at: int = 0
    revocation_token: str = ""
    scope_all_versions: bool = False

    def canonical(self) -> str:
        return (f"model_id={self.model_id}"
                f"&model_version={self.model_version}"
                f"&reason={self.reason.value}"
                f"&revoked_at={self.revoked_at}"
                f"&revoking_actor={self.revoking_actor}")

    def applies_to(self, p_model_id: str, p_model_version: str) -> bool:
        if p_model_id != self.model_id: return False
        if self.scope_all_versions: return True
        return p_model_version == self.model_version

class RevocationList:
    def __init__(self, log: TransparencyLog, signing_key: str):
        self.log = log
        self.signing_key = signing_key
        self.records: Dict[str, List[RevocationRecord]] = {}

    def revoke(self, model_id: str, model_version: str, actor: str, 
               reason: RevocationReason, detail: str, now: int) -> str:
        rec = RevocationRecord(model_id, model_version, actor, reason, detail, now, scope_all_versions=not model_version)
        rec.revocation_token = hmac_sha256_hex(self.signing_key, rec.canonical())
        self.records.setdefault(model_id, []).append(rec)
        
        self.log.append("PASSPORT_REVOKED", actor, model_id, 0,
                        f"REVOKED model_version={'*' if not model_version else model_version} reason={reason.value} detail={detail}", now)
        return rec.revocation_token

    def is_revoked(self, model_id: str, model_version: str) -> bool:
        return any(r.applies_to(model_id, model_version) for r in self.records.get(model_id, []))


# =============================================================================
# 6. PASSPORT REGISTRY
# =============================================================================
class VerifyStatus(Enum):
    OK = auto()
    REVOKED = auto()
    EXPIRED = auto()
    INVALID_SIGNATURE = auto()
    REGISTRY_VERSION_MISMATCH = auto()
    KEY_NOT_FOUND = auto()

@dataclass
class VerifyResult:
    status: VerifyStatus = VerifyStatus.INVALID_SIGNATURE
    verified_key_id: int = 0
    revocation_detail: str = ""

    def ok(self) -> bool:
        return self.status == VerifyStatus.OK

class PassportRegistry:
    def __init__(self, initial_key_material: str, registry_version: str, now: int, overlap_window: int = 3600):
        self.registry_version = registry_version
        self.log = TransparencyLog()
        self.key_store = KeyStore(overlap_window, self.log.make_key_event_logger("PassportRegistry"))
        self.revocation_list = RevocationList(self.log, initial_key_material)
        self.key_store.introduce_key(initial_key_material, now, "init")

    def issue(self, model_id: str, model_version: str, caps: Capabilities, policy_hash: str, now: int, ttl: int = 86400) -> SemanticPassport:
        p = SemanticPassport(
            model_id=model_id, model_version=model_version, registry_version=self.registry_version,
            capabilities=caps, policy_hash=policy_hash, issued_at=now, expires_at=now + ttl,
            signing_key_id=self.key_store.active_key_id, quorum_signed=False
        )
        p.sign(self.key_store.signing_key())
        self.log.append("PASSPORT_ISSUED", "PassportRegistry", model_id, p.signing_key_id, f"issued model_version={model_version}", now)
        return p

    def verify(self, p: SemanticPassport, now: int) -> VerifyResult:
        if self.revocation_list.is_revoked(p.model_id, p.model_version):
            return VerifyResult(status=VerifyStatus.REVOKED)
        if p.registry_version != self.registry_version:
            return VerifyResult(status=VerifyStatus.REGISTRY_VERSION_MISMATCH)
        if not p.is_valid(now):
            return VerifyResult(status=VerifyStatus.EXPIRED)

        verified_by = self.key_store.verify_with_any_valid_key(p.canonical_body(), p.signature, now)
        if verified_by == 0:
            return VerifyResult(status=VerifyStatus.INVALID_SIGNATURE)

        self.log.append("PASSPORT_VERIFIED", "PassportRegistry", p.model_id, verified_by, f"OK key_id={verified_by}", now)
        return VerifyResult(status=VerifyStatus.OK, verified_key_id=verified_by)

    def issue_recovery_token(self, original: SemanticPassport, incident_id: str, now: int, ttl: int = 3600) -> SemanticPassport:
        # Applies RECOVERY_CAPS_FLOOR as seen in e2e-example.cpp
        caps = Capabilities(
            classifier_authority=False,
            classifier_sensitivity=original.capabilities.classifier_sensitivity,
            bft_consensus=False,
            entropy_flush=False
        )
        p = self.issue(original.model_id, original.model_version, caps, original.policy_hash, now, ttl)
        p.recovery_token = f"RECOVERY:{incident_id}"
        p.flags |= PassportFlag.RECOVERED.value
        self.log.append("PASSPORT_RECOVERED", "PassportRegistry", p.model_id, p.signing_key_id, f"RECOVERY incident_id={incident_id}", now)
        return p


# =============================================================================
# 7. MULTI-PARTY ISSUANCE
# =============================================================================
class QuorumState(Enum):
    PENDING = "PENDING"
    FINALIZED = "FINALIZED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"

@dataclass
class QuorumRecord:
    proposal_id: str = ""
    proposed_passport: SemanticPassport = None
    partial_sigs: Dict[str, str] = field(default_factory=dict)
    rejections: Set[str] = field(default_factory=set)
    state: QuorumState = QuorumState.PENDING
    proposed_at: int = 0
    expires_at: int = 0
    threshold: int = 0

    def is_expired(self, now: int) -> bool:
        return now >= self.expires_at and self.state == QuorumState.PENDING
    def threshold_met(self) -> bool:
        return len(self.partial_sigs) >= self.threshold

class MultiPartyIssuer:
    def __init__(self, signers: List[str], threshold: int, registry_version: str, log: TransparencyLog, ttl: int = 300):
        if threshold == 0 or threshold > len(signers): raise ValueError("Invalid threshold")
        self.signers = signers
        self.threshold = threshold
        self.registry_version = registry_version
        self.log = log
        self.ttl = ttl
        self.proposals: Dict[str, QuorumRecord] = {}

    def _derive_signer_key(self, root_key: str, signer_id: str) -> str:
        return hmac_sha256_hex(root_key, f"UML001-SIGNER:{signer_id}")

    def propose(self, proposer_id: str, proposer_root: str, model_id: str, model_version: str, 
                caps: Capabilities, policy_hash: str, now: int, ttl: int = 86400) -> str:
        if proposer_id not in self.signers: raise ValueError("Unauthorized")
        
        p = SemanticPassport(model_id=model_id, model_version=model_version, registry_version=self.registry_version,
                             capabilities=caps, policy_hash=policy_hash, issued_at=now, expires_at=now+ttl)
        pid = sha256_hex(model_id + str(now))
        
        rec = QuorumRecord(proposal_id=pid, proposed_passport=p, proposed_at=now, expires_at=now+self.ttl, threshold=self.threshold)
        rec.partial_sigs[proposer_id] = hmac_sha256_hex(self._derive_signer_key(proposer_root, proposer_id), p.canonical_body())
        self.proposals[pid] = rec
        
        if self.threshold == 1: self._finalize(pid, now)
        return pid

    def countersign(self, signer_id: str, signer_root: str, pid: str, now: int) -> bool:
        if signer_id not in self.signers: raise ValueError("Unauthorized")
        rec = self.proposals[pid]
        if rec.is_expired(now) or rec.state != QuorumState.PENDING: raise ValueError("Invalid state")
        
        rec.partial_sigs[signer_id] = hmac_sha256_hex(self._derive_signer_key(signer_root, signer_id), rec.proposed_passport.canonical_body())
        if rec.threshold_met():
            self._finalize(pid, now)
            return True
        return False

    def _finalize(self, pid: str, now: int):
        rec = self.proposals[pid]
        concat = "".join(sig for _, sig in sorted(rec.partial_sigs.items()))
        rec.proposed_passport.signature = sha256_hex(rec.proposed_passport.canonical_body() + concat)
        rec.state = QuorumState.FINALIZED

    def verify_quorum_passport(self, p: SemanticPassport, root_key: str, now: int) -> bool:
        if not p.is_valid(now): return False
        for pid, rec in self.proposals.items():
            if rec.proposed_passport.model_id == p.model_id and rec.state == QuorumState.FINALIZED:
                concat = "".join(sig for _, sig in sorted(rec.partial_sigs.items()))
                expected = sha256_hex(p.canonical_body() + concat)
                return constant_eq(expected, p.signature)
        return False


# =============================================================================
# 8. HANDSHAKE (Rev 1.2)
# =============================================================================
class EphemeralKeyPair:
    def __init__(self):
        self.private_hex = generate_nonce(32)
        prv_bytes = hex_to_bytes(self.private_hex)
        pub_bytes = hkdf_sha256(prv_bytes, b"ephemeral-public-salt", b"uml001-epk-v1", 32)
        self.public_hex = bytes_to_hex(pub_bytes)

    def derive_shared_secret(self, peer_public_hex: str, local_nonce: str, remote_nonce: str) -> str:
        local_priv = hex_to_bytes(self.private_hex)
        peer_pub = hex_to_bytes(peer_public_hex)
        ikm = bytes(a ^ b for a, b in zip(local_priv, peer_pub))
        salt = (local_nonce + remote_nonce).encode('utf-8')
        key_bytes = hkdf_sha256(ikm, salt, b"uml001-session-key-v1", 32)
        return bytes_to_hex(key_bytes)

    def destroy_private_key(self):
        self.private_hex = ""

class TransportBindingType(Enum):
    TLS_CERT_FINGERPRINT = auto()
    TCP_ADDRESS = auto()
    UNIX_SOCKET = auto()
    NONE = auto()

@dataclass
class TransportIdentity:
    type: TransportBindingType = TransportBindingType.NONE
    value: str = ""

    def binding_token(self) -> str:
        prefix = {
            TransportBindingType.TLS_CERT_FINGERPRINT: "tls:",
            TransportBindingType.TCP_ADDRESS: "tcp:",
            TransportBindingType.UNIX_SOCKET: "unix:",
            TransportBindingType.NONE: "none:"
        }.get(self.type, "none:")
        return f"{prefix}{self.value if self.type != TransportBindingType.NONE else 'unbound'}"

    def is_strong(self) -> bool:
        return self.type in (TransportBindingType.TLS_CERT_FINGERPRINT, TransportBindingType.UNIX_SOCKET)

class NonceCache:
    def __init__(self): self.seen = set()
    def consume(self, nonce: str) -> bool:
        if nonce in self.seen: return False
        self.seen.add(nonce)
        return True

@dataclass
class SessionContext:
    session_id: str = ""
    session_key_hex: str = ""
    initiator_model_id: str = ""
    responder_model_id: str = ""
    forward_secrecy: bool = False

    def derive_direction_key(self, direction: str) -> str:
        kb = hex_to_bytes(self.session_key_hex)
        return bytes_to_hex(hkdf_sha256(kb, self.session_id.encode(), f"uml001-direction-{direction}".encode(), 32))

    def authenticate_payload(self, payload: str, direction: str) -> str:
        dk = hex_to_bytes(self.derive_direction_key(direction))
        return hmac_sha256_hex(dk.decode('latin1', errors='ignore'), payload)  # Note: HMAC needs bytes key

class HandshakeValidator:
    def __init__(self, registry: PassportRegistry, local_passport: SemanticPassport, 
                 schema: str, transport: TransportIdentity, cache: NonceCache, now: int):
        self.registry = registry
        self.local_passport = local_passport
        self.local_schema = schema
        self.local_transport = transport
        self.nonce_cache = cache
        self.now = now
        self.local_nonce = ""
        self.local_ephemeral = None

    def build_hello(self) -> Dict[str, Any]:
        self.local_nonce = generate_nonce()
        self.local_ephemeral = EphemeralKeyPair()
        return {
            "passport": self.local_passport, "session_nonce": self.local_nonce, 
            "proposed_schema": self.local_schema, "ephemeral_public_hex": self.local_ephemeral.public_hex,
            "transport": self.local_transport
        }

    def validate_hello(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        if not self.nonce_cache.consume(msg["session_nonce"]): return {"accepted": False, "reason": "REPLAY_DETECTED"}
        if not self.registry.verify(msg["passport"], self.now).ok(): return {"accepted": False, "reason": "PASSPORT_INVALID"}
        
        self.local_nonce = generate_nonce()
        self.local_ephemeral = EphemeralKeyPair()
        
        sid_material = msg["session_nonce"] + self.local_nonce + msg["transport"].binding_token() + self.local_transport.binding_token()
        session_id = sha256_hex(sid_material)
        
        shared_secret = self.local_ephemeral.derive_shared_secret(msg["ephemeral_public_hex"], self.local_nonce, msg["session_nonce"])
        sess_key = bytes_to_hex(hkdf_sha256(hex_to_bytes(shared_secret), session_id.encode(), b"uml001-session-key-v1", 32))
        
        ctx = SessionContext(session_id=session_id, session_key_hex=sess_key, forward_secrecy=True)
        self.local_ephemeral.destroy_private_key()
        
        ack = {
            "passport": self.local_passport, "session_nonce": self.local_nonce,
            "session_id": session_id, "ephemeral_public_hex": self.local_ephemeral.public_hex,
            "transport": self.local_transport
        }
        return {"accepted": True, "ack": ack, "session": ctx}


# =============================================================================
# 9. CLASSIFIER & POLICY
# =============================================================================
@dataclass
class SemanticScore:
    payload_hash: str = ""
    authority: float = 0.0
    sensitivity: float = 0.0
    authority_confidence: float = 0.0
    sensitivity_confidence: float = 0.0

class PolicyAction(Enum): ALLOW = 1; DENY = 2; FLAG = 3
class LogLevel(Enum): INFO = 1; WARN = 2; ALERT = 3

@dataclass
class TrustCriteria:
    min_authority_confidence: float = 0.8
    min_sensitivity_confidence: float = 0.8
    def is_trusted(self, s: SemanticScore) -> bool:
        return s.authority_confidence >= self.min_authority_confidence and s.sensitivity_confidence >= self.min_sensitivity_confidence

@dataclass
class ScopeCriteria:
    authority_min: Optional[float] = None
    authority_max: Optional[float] = None
    sensitivity_min: Optional[float] = None
    sensitivity_max: Optional[float] = None
    def is_within_scope(self, s: SemanticScore) -> bool:
        if self.authority_min is not None and s.authority < self.authority_min: return False
        if self.authority_max is not None and s.authority > self.authority_max: return False
        if self.sensitivity_min is not None and s.sensitivity < self.sensitivity_min: return False
        if self.sensitivity_max is not None and s.sensitivity > self.sensitivity_max: return False
        return True

@dataclass
class PolicyRule:
    rule_id: str
    trust: TrustCriteria
    scope: ScopeCriteria
    action: PolicyAction = PolicyAction.DENY

class PolicyEngine:
    def __init__(self, expected_registry: str, rules: List[PolicyRule]):
        self.expected_registry = expected_registry
        self.rules = rules

    def evaluate(self, score: SemanticScore, active_registry: str, passport: Optional[SemanticPassport] = None) -> PolicyAction:
        if active_registry != self.expected_registry: return PolicyAction.DENY
        
        # Apply TRUST_GATE floor from e2e-example.cpp if recovered
        floor = 0.95 if (passport and passport.is_recovered()) else 0.0

        for rule in self.rules:
            if score.authority_confidence < max(rule.trust.min_authority_confidence, floor): continue
            if score.sensitivity_confidence < max(rule.trust.min_sensitivity_confidence, floor): continue
            if rule.scope.is_within_scope(score): return rule.action
        return PolicyAction.DENY


# =============================================================================
# 10. SESSION & FLUSH
# =============================================================================
class SessionState(Enum):
    INIT = 1; ACTIVE = 2; SUSPECT = 3; QUARANTINE = 4; FLUSHING = 5; CLOSED = 6

class Session:
    def __init__(self, session_id: str, warp_threshold: float = 3.0):
        self.session_id = session_id
        self.warp_threshold = warp_threshold
        self.state = SessionState.INIT
        self.warp_score = 0.0

    def process_decision(self, action: PolicyAction) -> bool:
        if self.state in (SessionState.QUARANTINE, SessionState.FLUSHING, SessionState.CLOSED): return False
        
        if action == PolicyAction.DENY: self.warp_score += 1.0
        elif action == PolicyAction.FLAG: self.warp_score += 0.5
        elif action == PolicyAction.ALLOW: self.warp_score = max(0.0, self.warp_score - 0.1)

        if self.warp_score >= self.warp_threshold:
            self.state = SessionState.QUARANTINE
            return False
        if action == PolicyAction.DENY: self.state = SessionState.SUSPECT
        return action != PolicyAction.DENY


# =============================================================================
# 11. BFT CONSENSUS
# =============================================================================
def geometric_median_2d(points: List[Tuple[float, float]], iterations: int = 100, epsilon: float = 1e-6) -> Tuple[float, float]:
    if not points: raise ValueError()
    if len(points) == 1: return points[0]
    
    mx = sum(p[0] for p in points) / len(points)
    my = sum(p[1] for p in points) / len(points)
    
    for _ in range(iterations):
        num_x = num_y = denom = 0.0
        for px, py in points:
            dist = math.hypot(px - mx, py - my)
            if dist < epsilon: continue
            w = 1.0 / dist
            num_x += px * w
            num_y += py * w
            denom += w
        if denom < epsilon: break
        new_mx, new_my = num_x / denom, num_y / denom
        if abs(new_mx - mx) < epsilon and abs(new_my - my) < epsilon: break
        mx, my = new_mx, new_my
    return mx, my


# =============================================================================
# 12. AUDIT VAULT
# =============================================================================
@dataclass
class VaultEntry:
    entry_id: str = ""
    prev_hash: str = ""
    sequence: int = 0
    event_type: str = ""
    payload_hash: str = ""

    def canonical(self) -> str:
        return f"entry_id={self.entry_id}&event_type={self.event_type}&payload_hash={self.payload_hash}&prev_hash={self.prev_hash}&sequence={self.sequence}"

class ColdAuditVault:
    def __init__(self):
        self.entries: List[VaultEntry] = []
    
    def append(self, event_type: str, payload_hash: str) -> str:
        prev = self.entries[-1].entry_id if self.entries else "GENESIS"
        seq = len(self.entries)
        e = VaultEntry(entry_id="", prev_hash=prev, sequence=seq, event_type=event_type, payload_hash=payload_hash)
        e.entry_id = sha256_hex(e.canonical())
        self.entries.append(e)
        return e.entry_id