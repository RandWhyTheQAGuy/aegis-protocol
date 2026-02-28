"""
aegis_protocol.handshake
----------------
HandshakeValidator rev 1.2 — 3-message protocol with ephemeral DH,
forward secrecy, replay detection, and transport binding.
"""

import dataclasses
import enum
import time
from typing import Dict, Optional, Set, Tuple

from aegis_protocol.crypto_utils import (
    sha256_hex, hmac_sha256, generate_nonce,
    ephemeral_dh_exchange, compute_shared_secret, derive_direction_key,
)
from aegis_protocol.passport import SemanticPassport


# ---------------------------------------------------------------------------
# Transport Identity
# ---------------------------------------------------------------------------

class TransportBindingType(enum.Enum):
    TLS_CERT_FINGERPRINT = "TLS_CERT_FINGERPRINT"
    TCP_ADDRESS          = "TCP_ADDRESS"
    UNIX_SOCKET          = "UNIX_SOCKET"


@dataclasses.dataclass
class TransportIdentity:
    binding_type: TransportBindingType
    value:        str

    def is_strong(self) -> bool:
        return self.binding_type == TransportBindingType.TLS_CERT_FINGERPRINT


# ---------------------------------------------------------------------------
# SessionContext
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class SessionContext:
    session_id:          str
    session_key_hex:     str
    forward_secrecy:     bool
    initiator_model_id:  str
    responder_model_id:  str

    def derive_direction_key(self, direction: str) -> str:
        return derive_direction_key(self.session_key_hex, direction)

    def authenticate_payload(self, payload: str, direction: str) -> str:
        dk = self.derive_direction_key(direction)
        return hmac_sha256(dk, payload)


# ---------------------------------------------------------------------------
# NonceCache
# ---------------------------------------------------------------------------

class NonceCache:
    """
    Per-party nonce store with TTL-bounded replay detection.
    """
    DEFAULT_TTL = 300
    DEFAULT_MAX = 10_000

    def __init__(self, ttl_seconds: int = DEFAULT_TTL, max_entries: int = DEFAULT_MAX,
                 prefix: str = ""):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._prefix = prefix
        self._store: Dict[str, int] = {}  # nonce -> timestamp

    def _key(self, nonce: str) -> str:
        return self._prefix + nonce

    def check_and_add(self, nonce: str, now: int) -> bool:
        """Return True if the nonce is fresh (not seen). Adds it to the store."""
        self._evict(now)
        k = self._key(nonce)
        if k in self._store:
            return False
        if len(self._store) >= self._max:
            return False
        self._store[k] = now
        return True

    def _evict(self, now: int) -> None:
        expired = [k for k, ts in self._store.items() if now - ts > self._ttl]
        for k in expired:
            del self._store[k]


# ---------------------------------------------------------------------------
# Message types (plain dicts for simplicity)
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class HelloMessage:
    schema:          str
    nonce:           str
    public_key_hex:  str
    model_id:        str
    transport_type:  str
    transport_value: str
    timestamp:       int
    passport_sig:    str


@dataclasses.dataclass
class AckMessage:
    schema:          str
    hello_nonce:     str
    ack_nonce:       str
    public_key_hex:  str
    model_id:        str
    transport_type:  str
    transport_value: str
    timestamp:       int


@dataclasses.dataclass
class ConfirmMessage:
    schema:    str
    ack_nonce: str
    session_id: str
    timestamp: int


@dataclasses.dataclass
class AckResult:
    accepted:      bool
    ack:           Optional[AckMessage] = None
    reject_reason: str = ""


@dataclasses.dataclass
class ProcessAckResult:
    accepted:      bool
    confirm:       Optional[ConfirmMessage] = None
    session:       Optional[SessionContext] = None
    reject_reason: str = ""


@dataclasses.dataclass
class ConfirmResult:
    accepted:      bool
    session:       Optional[SessionContext] = None
    reject_reason: str = ""


# ---------------------------------------------------------------------------
# HandshakeValidator
# ---------------------------------------------------------------------------

class HandshakeValidator:
    def __init__(
        self,
        registry,
        passport: SemanticPassport,
        schema: str,
        transport: TransportIdentity,
        nonce_cache: NonceCache,
        now: int,
        reject_recovered: bool = False,
        require_strong: bool = True,
    ):
        self._registry = registry
        self._passport = passport
        self._schema = schema
        self._transport = transport
        self._nc = nonce_cache
        self._now = now
        self._reject_recovered = reject_recovered
        self._require_strong = require_strong

        # Ephemeral DH keypair
        self._pub_key, self._priv_key = ephemeral_dh_exchange()

        # State for multi-step protocol
        self._hello_nonce: Optional[str] = None
        self._ack_nonce:   Optional[str] = None
        self._peer_pub:    Optional[str] = None
        self._session:     Optional[SessionContext] = None

    # ------------------------------------------------------------------
    # Step 1: Initiator builds HELLO
    # ------------------------------------------------------------------

    def build_hello(self, schema: str) -> HelloMessage:
        nonce = generate_nonce()
        self._hello_nonce = nonce
        sig = hmac_sha256(self._passport.signature, nonce)
        return HelloMessage(
            schema=schema,
            nonce=nonce,
            public_key_hex=self._pub_key,
            model_id=self._passport.model_id,
            transport_type=self._transport.binding_type.value,
            transport_value=self._transport.value,
            timestamp=self._now,
            passport_sig=sig,
        )

    # ------------------------------------------------------------------
    # Step 2: Responder validates HELLO → sends ACK
    # ------------------------------------------------------------------

    def validate_hello(self, hello: HelloMessage) -> AckResult:
        # Schema check
        if hello.schema != self._schema:
            return AckResult(accepted=False, reject_reason="REJECT_SCHEMA_MISMATCH")

        # Transport check
        if self._require_strong:
            hello_transport_type = TransportBindingType(hello.transport_type)
            if not TransportIdentity(hello_transport_type, hello.transport_value).is_strong():
                return AckResult(accepted=False, reject_reason="REJECT_TRANSPORT_MISMATCH")

        # Replay check
        if not self._nc.check_and_add(hello.nonce, self._now):
            return AckResult(accepted=False, reject_reason="REJECT_REPLAY_DETECTED")

        # Passport verification (look up sender by model_id)
        from aegis_protocol.passport import VerifyStatus
        rev = self._registry.revocation_list().get_revocation(hello.model_id, "")
        if rev is not None:
            return AckResult(accepted=False, reject_reason="REJECT_PASSPORT_REVOKED")

        # Build ACK
        ack_nonce = generate_nonce()
        self._ack_nonce    = ack_nonce
        self._peer_pub     = hello.public_key_hex
        self._hello_nonce  = hello.nonce          # store so _build_session can use it
        self._initiator_model = hello.model_id

        ack = AckMessage(
            schema=hello.schema,
            hello_nonce=hello.nonce,
            ack_nonce=ack_nonce,
            public_key_hex=self._pub_key,
            model_id=self._passport.model_id,
            transport_type=self._transport.binding_type.value,
            transport_value=self._transport.value,
            timestamp=self._now,
        )
        return AckResult(accepted=True, ack=ack)

    # ------------------------------------------------------------------
    # Step 3a: Initiator processes ACK → sends CONFIRM
    # ------------------------------------------------------------------

    def process_ack(self, ack: AckMessage) -> ProcessAckResult:
        if ack.hello_nonce != self._hello_nonce:
            return ProcessAckResult(accepted=False, reject_reason="REJECT_NONCE_MISMATCH")

        self._ack_nonce = ack.ack_nonce
        self._peer_pub  = ack.public_key_hex

        session = self._build_session(
            initiator_model=self._passport.model_id,
            responder_model=ack.model_id,
        )
        self._session = session

        confirm = ConfirmMessage(
            schema=self._schema,
            ack_nonce=ack.ack_nonce,
            session_id=session.session_id,
            timestamp=self._now,
        )
        return ProcessAckResult(accepted=True, confirm=confirm, session=session)

    # ------------------------------------------------------------------
    # Step 3b: Responder validates CONFIRM
    # ------------------------------------------------------------------

    def validate_confirm(self, confirm: ConfirmMessage) -> ConfirmResult:
        if confirm.ack_nonce != self._ack_nonce:
            return ConfirmResult(accepted=False, reject_reason="REJECT_NONCE_MISMATCH")

        session = self._build_session(
            initiator_model=getattr(self, '_initiator_model', self._hello_nonce),
            responder_model=self._passport.model_id,
            session_id_override=confirm.session_id,
        )
        self._session = session
        return ConfirmResult(accepted=True, session=session)

    # ------------------------------------------------------------------
    # Session key derivation
    # ------------------------------------------------------------------

    def _build_session(
        self,
        initiator_model: str,
        responder_model: str,
        session_id_override: Optional[str] = None,
    ) -> SessionContext:
        shared_secret = compute_shared_secret(self._priv_key, self._peer_pub)
        session_key = hmac_sha256(shared_secret,
                                   f"{self._hello_nonce}:{self._ack_nonce}")
        if session_id_override:
            sid = session_id_override
        else:
            sid = sha256_hex(f"{session_key}:{self._now}")

        return SessionContext(
            session_id=sid,
            session_key_hex=session_key,
            forward_secrecy=True,
            initiator_model_id=initiator_model,
            responder_model_id=responder_model,
        )
