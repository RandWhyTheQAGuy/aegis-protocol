"""
aegis.handshake
~~~~~~~~~~~~~~~
Three-message capability negotiation handshake (HELLO / HELLO_ACK / HELLO_CONFIRM).

Agents MUST complete a successful handshake before any payload exchange begins.
The handshake establishes a shared session_id, verifies Passport validity on
both sides, and confirms schema and registry compatibility.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .crypto import sha256_hex, hmac_sha256_hex, hmac_verify, generate_nonce
from .passport import SemanticPassport, PassportRegistry
from .exceptions import (
    HandshakeRejectError,
    HandshakeSchemaMismatchError,
    PassportExpiredError,
    PassportSignatureError,
    PassportRegistryMismatchError,
)


# ---------------------------------------------------------------------------
# Reject reason constants (match spec/schemas/handshake.schema.json)
# ---------------------------------------------------------------------------
REJECT_PASSPORT_INVALID   = "REJECT_PASSPORT_INVALID"
REJECT_PASSPORT_EXPIRED   = "REJECT_PASSPORT_EXPIRED"
REJECT_REGISTRY_MISMATCH  = "REJECT_REGISTRY_MISMATCH"
REJECT_SCHEMA_MISMATCH    = "REJECT_SCHEMA_MISMATCH"
REJECT_POLICY_MISMATCH    = "REJECT_POLICY_MISMATCH"
REJECT_RECOVERY_REQUIRED  = "REJECT_RECOVERY_REQUIRED"


# ---------------------------------------------------------------------------
# Message dataclasses
# ---------------------------------------------------------------------------

@dataclass
class HelloMessage:
    """Message 1: initiator -> responder."""
    passport:        SemanticPassport
    session_nonce:   str  # 32-byte random hex
    proposed_schema: str

    def to_dict(self) -> dict:
        return {
            "type": "UML002_HELLO",
            "passport": self.passport.to_dict(),
            "session_nonce": self.session_nonce,
            "proposed_schema": self.proposed_schema,
        }


@dataclass
class HelloAckMessage:
    """Message 2: responder -> initiator."""
    passport:        SemanticPassport
    session_nonce:   str  # initiator_nonce + responder_nonce (128 hex chars)
    accepted_schema: str
    session_id:      str  # SHA-256(initiator_nonce + responder_nonce)

    def to_dict(self) -> dict:
        return {
            "type": "UML002_HELLO_ACK",
            "passport": self.passport.to_dict(),
            "session_nonce": self.session_nonce,
            "accepted_schema": self.accepted_schema,
            "session_id": self.session_id,
        }


@dataclass
class HelloConfirmMessage:
    """Message 3: initiator -> responder."""
    session_id: str
    signature:  str  # HMAC-SHA256(session_id, initiator_registry_key)

    def to_dict(self) -> dict:
        return {
            "type": "UML002_HELLO_CONFIRM",
            "session_id": self.session_id,
            "signature": self.signature,
        }


@dataclass
class HelloRejectMessage:
    """Sent by either party to abort the handshake."""
    reason: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "type": "UML002_HELLO_REJECT",
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class HandshakeResult:
    """Outcome of a completed handshake.

    Attributes:
        accepted:          True if handshake completed successfully.
        session_id:        Derived session identifier (non-empty on success).
        reject_reason:     Reject reason code (non-empty on failure).
        peer_passport:     The peer's verified passport (set on success).
    """
    accepted:       bool = False
    session_id:     str = ""
    reject_reason:  str = ""
    peer_passport:  Optional[SemanticPassport] = None


# ---------------------------------------------------------------------------
# Initiator
# ---------------------------------------------------------------------------

class HandshakeInitiator:
    """The initiating side of the UML-001 handshake.

    Sends HELLO, validates HELLO_ACK, sends HELLO_CONFIRM.

    Args:
        local_passport:   This agent's own signed Passport.
        registry:         The PassportRegistry for verifying the peer's Passport.
        schema_version:   Payload schema version to propose.
        registry_key:     This agent's registry key for signing HELLO_CONFIRM.
        now:              Timestamp override (for testing).

    Example::

        initiator = HandshakeInitiator(
            local_passport=my_passport,
            registry=registry,
            schema_version="uml001-payload-v0.1",
            registry_key=REGISTRY_KEY,
        )

        hello = initiator.create_hello()
        # ... send hello, receive ack ...
        result = initiator.process_ack(ack_message)
        if not result.accepted:
            raise HandshakeRejectError(result.reject_reason)

        confirm = initiator.create_confirm(result.session_id)
        # ... send confirm ...
    """

    def __init__(
        self,
        local_passport: SemanticPassport,
        registry: PassportRegistry,
        schema_version: str,
        registry_key: str,
        now: Optional[int] = None,
    ) -> None:
        self._passport      = local_passport
        self._registry      = registry
        self._schema        = schema_version
        self._registry_key  = registry_key
        self._now           = now
        self._nonce         = generate_nonce(32)

    def create_hello(self) -> HelloMessage:
        """Build and return the HELLO message."""
        return HelloMessage(
            passport=self._passport,
            session_nonce=self._nonce,
            proposed_schema=self._schema,
        )

    def process_ack(self, ack: HelloAckMessage) -> HandshakeResult:
        """Validate the HELLO_ACK from the responder.

        Args:
            ack: The :class:`HelloAckMessage` received from the responder.

        Returns:
            :class:`HandshakeResult` with ``accepted=True`` on success.
        """
        now = self._now if self._now is not None else int(time.time())
        result = HandshakeResult()

        # Verify peer passport
        try:
            self._registry.verify(ack.passport, now)
        except PassportExpiredError:
            result.reject_reason = REJECT_PASSPORT_EXPIRED
            return result
        except PassportRegistryMismatchError:
            result.reject_reason = REJECT_REGISTRY_MISMATCH
            return result
        except PassportSignatureError:
            result.reject_reason = REJECT_PASSPORT_INVALID
            return result

        # Verify schema compatibility
        if ack.accepted_schema != self._schema:
            result.reject_reason = REJECT_SCHEMA_MISMATCH
            return result

        # Verify session_id derivation
        expected_session_id = sha256_hex(ack.session_nonce)
        if ack.session_id != expected_session_id:
            result.reject_reason = REJECT_PASSPORT_INVALID
            return result

        result.accepted      = True
        result.session_id    = ack.session_id
        result.peer_passport = ack.passport
        return result

    def create_confirm(self, session_id: str) -> HelloConfirmMessage:
        """Build the HELLO_CONFIRM message.

        Args:
            session_id: The session_id from the validated HELLO_ACK.

        Returns:
            :class:`HelloConfirmMessage`.
        """
        sig = hmac_sha256_hex(self._registry_key, session_id)
        return HelloConfirmMessage(session_id=session_id, signature=sig)

    @property
    def nonce(self) -> str:
        return self._nonce


# ---------------------------------------------------------------------------
# Responder
# ---------------------------------------------------------------------------

class HandshakeResponder:
    """The responding side of the UML-001 handshake.

    Receives HELLO, sends HELLO_ACK, validates HELLO_CONFIRM.

    Args:
        local_passport:          This agent's own signed Passport.
        registry:                The PassportRegistry for verifying the peer's Passport.
        schema_version:          Supported payload schema version.
        registry_key:            This agent's registry key for HELLO_CONFIRM verification.
        reject_recovered_peers:  If True, reject peers carrying a recovery token.
        now:                     Timestamp override (for testing).

    Example::

        responder = HandshakeResponder(
            local_passport=my_passport,
            registry=registry,
            schema_version="uml001-payload-v0.1",
            registry_key=REGISTRY_KEY,
        )

        result, ack_or_reject = responder.process_hello(hello_message)
        # send ack_or_reject to initiator

        if result.accepted:
            ok = responder.process_confirm(confirm_message, result.session_id)
    """

    def __init__(
        self,
        local_passport: SemanticPassport,
        registry: PassportRegistry,
        schema_version: str,
        registry_key: str,
        reject_recovered_peers: bool = False,
        now: Optional[int] = None,
    ) -> None:
        self._passport       = local_passport
        self._registry       = registry
        self._schema         = schema_version
        self._registry_key   = registry_key
        self._reject_recovered = reject_recovered_peers
        self._now            = now
        self._responder_nonce = generate_nonce(32)

    def process_hello(
        self, hello: HelloMessage
    ) -> tuple:
        """Validate a HELLO message and produce HELLO_ACK or HELLO_REJECT.

        Args:
            hello: The :class:`HelloMessage` received from the initiator.

        Returns:
            Tuple of (:class:`HandshakeResult`,
            :class:`HelloAckMessage` | :class:`HelloRejectMessage`).
        """
        now = self._now if self._now is not None else int(time.time())
        result = HandshakeResult()

        # Verify peer passport
        try:
            self._registry.verify(hello.passport, now)
        except PassportExpiredError:
            reject = HelloRejectMessage(REJECT_PASSPORT_EXPIRED)
            result.reject_reason = REJECT_PASSPORT_EXPIRED
            return result, reject
        except PassportRegistryMismatchError:
            reject = HelloRejectMessage(REJECT_REGISTRY_MISMATCH)
            result.reject_reason = REJECT_REGISTRY_MISMATCH
            return result, reject
        except PassportSignatureError:
            reject = HelloRejectMessage(REJECT_PASSPORT_INVALID)
            result.reject_reason = REJECT_PASSPORT_INVALID
            return result, reject

        # Check for recovery token if policy requires
        if self._reject_recovered and hello.passport.is_recovered():
            reject = HelloRejectMessage(
                REJECT_RECOVERY_REQUIRED,
                detail="Peer carries recovery token; manual review required",
            )
            result.reject_reason = REJECT_RECOVERY_REQUIRED
            return result, reject

        # Schema compatibility
        if hello.proposed_schema != self._schema:
            reject = HelloRejectMessage(
                REJECT_SCHEMA_MISMATCH,
                detail=f"Expected {self._schema!r}, got {hello.proposed_schema!r}",
            )
            result.reject_reason = REJECT_SCHEMA_MISMATCH
            return result, reject

        # Derive session_id from combined nonces
        combined_nonce = hello.session_nonce + self._responder_nonce
        session_id     = sha256_hex(combined_nonce)

        result.accepted      = True
        result.session_id    = session_id
        result.peer_passport = hello.passport

        ack = HelloAckMessage(
            passport=self._passport,
            session_nonce=combined_nonce,
            accepted_schema=self._schema,
            session_id=session_id,
        )
        return result, ack

    def process_confirm(
        self, confirm: HelloConfirmMessage, expected_session_id: str
    ) -> bool:
        """Validate the HELLO_CONFIRM from the initiator.

        Args:
            confirm:             The :class:`HelloConfirmMessage`.
            expected_session_id: Session ID from the HELLO_ACK.

        Returns:
            True if the confirm is valid; False otherwise.
        """
        if confirm.session_id != expected_session_id:
            return False
        return hmac_verify(self._registry_key, confirm.session_id, confirm.signature)
