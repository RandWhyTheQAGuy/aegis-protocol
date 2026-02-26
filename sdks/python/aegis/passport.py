"""
aegis.passport
~~~~~~~~~~~~~~
SemanticPassport dataclass, Capabilities, and PassportRegistry.

The Passport is the identity and credential layer for all UML-001 agent
communication. Every agent MUST present a valid, verified Passport before
any payload exchange begins.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from .crypto import hmac_sha256_hex, hmac_verify, canonical_sort
from .exceptions import (
    PassportExpiredError,
    PassportSignatureError,
    PassportRegistryMismatchError,
)


PASSPORT_VERSION = "0.1"
PROTOCOL = "UML-001"


@dataclass
class Capabilities:
    """Flags declaring which UML-001 features an agent supports."""

    classifier_authority: bool = False
    classifier_sensitivity: bool = False
    bft_consensus: bool = False
    entropy_flush: bool = False

    @classmethod
    def full(cls) -> "Capabilities":
        """All capabilities enabled. Convenience constructor."""
        return cls(
            classifier_authority=True,
            classifier_sensitivity=True,
            bft_consensus=True,
            entropy_flush=True,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SemanticPassport:
    """Signed credential attesting to an agent's identity and policy compliance.

    Passports are issued by :class:`PassportRegistry` and verified by peer
    agents during the capability handshake. The signature field is set by
    calling :meth:`sign` and verified by :meth:`verify`.

    Fields correspond 1:1 with ``spec/schemas/passport.schema.json``.
    """

    model_id: str
    model_version: str
    registry_version: str
    capabilities: Capabilities
    policy_hash: str
    issued_at: int
    expires_at: int
    passport_version: str = PASSPORT_VERSION
    protocol: str = PROTOCOL
    recovery_token: Optional[str] = None
    signature: str = ""

    # ------------------------------------------------------------------
    # Validity checks
    # ------------------------------------------------------------------

    def is_valid(self, now: Optional[int] = None) -> bool:
        """Return True if the passport is not expired.

        Args:
            now: Unix timestamp to check against. Defaults to current time.
        """
        now = now if now is not None else int(time.time())
        return now >= self.issued_at and now < self.expires_at

    def is_recovered(self) -> bool:
        """Return True if this passport carries a post-Entropy-Flush recovery token."""
        return bool(self.recovery_token)

    # ------------------------------------------------------------------
    # Signing and verification
    # ------------------------------------------------------------------

    def _canonical_body(self) -> str:
        """Produce the deterministic string used as the HMAC message body."""
        body = {
            "capabilities": self.capabilities.to_dict(),
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "passport_version": self.passport_version,
            "policy_hash": self.policy_hash,
            "protocol": self.protocol,
            "recovery_token": self.recovery_token or "",
            "registry_version": self.registry_version,
        }
        return canonical_sort(body)

    def sign(self, registry_key: str) -> "SemanticPassport":
        """Sign this passport with *registry_key* and set :attr:`signature`.

        Args:
            registry_key: The Registry's HMAC secret key.

        Returns:
            Self, for chaining.
        """
        self.signature = hmac_sha256_hex(registry_key, self._canonical_body())
        return self

    def verify(self, registry_key: str) -> bool:
        """Return True if the signature is valid for *registry_key*.

        Uses constant-time comparison to prevent timing attacks.
        """
        if not self.signature:
            return False
        return hmac_verify(registry_key, self._canonical_body(), self.signature)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict matching the passport schema."""
        return {
            "passport_version": self.passport_version,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "protocol": self.protocol,
            "registry_version": self.registry_version,
            "capabilities": self.capabilities.to_dict(),
            "policy_hash": self.policy_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "recovery_token": self.recovery_token,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SemanticPassport":
        """Deserialize from a dict (e.g., parsed from JSON).

        Does not verify the signature. Call :meth:`verify` explicitly.
        """
        caps_data = data.get("capabilities", {})
        caps = Capabilities(
            classifier_authority=caps_data.get("classifier_authority", False),
            classifier_sensitivity=caps_data.get("classifier_sensitivity", False),
            bft_consensus=caps_data.get("bft_consensus", False),
            entropy_flush=caps_data.get("entropy_flush", False),
        )
        return cls(
            model_id=data["model_id"],
            model_version=data["model_version"],
            registry_version=data["registry_version"],
            capabilities=caps,
            policy_hash=data["policy_hash"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            passport_version=data.get("passport_version", PASSPORT_VERSION),
            protocol=data.get("protocol", PROTOCOL),
            recovery_token=data.get("recovery_token"),
            signature=data.get("signature", ""),
        )

    def __repr__(self) -> str:
        return (
            f"SemanticPassport(model_id={self.model_id!r}, "
            f"registry_version={self.registry_version!r}, "
            f"expires_at={self.expires_at})"
        )


class PassportRegistry:
    """Issues and verifies Semantic Passports.

    Acts as the cryptographic root of trust for a UML-001 agent cluster.
    In production, the ``registry_key`` is rotated on schedule and after
    any Perspective Warp incident.

    Args:
        registry_key:      HMAC secret key. Keep this secret.
        registry_version:  Semver version of the current anchor set.
    """

    def __init__(self, registry_key: str, registry_version: str) -> None:
        if not registry_key:
            raise ValueError("PassportRegistry: registry_key must not be empty")
        if not registry_version:
            raise ValueError("PassportRegistry: registry_version must not be empty")
        self._key = registry_key
        self._version = registry_version

    @property
    def registry_version(self) -> str:
        return self._version

    def issue(
        self,
        model_id: str,
        model_version: str,
        capabilities: Capabilities,
        policy_hash: str,
        now: Optional[int] = None,
        ttl_seconds: int = 86_400,
    ) -> SemanticPassport:
        """Issue and sign a new Semantic Passport.

        Args:
            model_id:      Unique agent identifier.
            model_version: Agent implementation version.
            capabilities:  Supported UML-001 features.
            policy_hash:   SHA-256 of the active policy rule set.
            now:           Issue timestamp. Defaults to current time.
            ttl_seconds:   Validity window in seconds. Default 24 hours.

        Returns:
            A signed :class:`SemanticPassport`.
        """
        now = now if now is not None else int(time.time())
        passport = SemanticPassport(
            model_id=model_id,
            model_version=model_version,
            registry_version=self._version,
            capabilities=capabilities,
            policy_hash=policy_hash,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        passport.sign(self._key)
        return passport

    def verify(self, passport: SemanticPassport, now: Optional[int] = None) -> None:
        """Verify a passport's signature, expiry, and registry version.

        Args:
            passport: Passport to verify.
            now:      Timestamp for expiry check. Defaults to current time.

        Raises:
            PassportExpiredError:           Passport TTL has elapsed.
            PassportRegistryMismatchError:  Registry version mismatch.
            PassportSignatureError:         HMAC verification failed.
        """
        now = now if now is not None else int(time.time())

        if not passport.is_valid(now):
            raise PassportExpiredError(passport.model_id, passport.expires_at, now)

        if passport.registry_version != self._version:
            raise PassportRegistryMismatchError(passport.registry_version, self._version)

        if not passport.verify(self._key):
            raise PassportSignatureError(passport.model_id)

    def issue_recovery_token(
        self,
        passport: SemanticPassport,
        incident_id: str,
        now: Optional[int] = None,
        ttl_seconds: int = 3_600,
    ) -> SemanticPassport:
        """Re-issue a passport with a recovery token after an Entropy Flush.

        The recovery token signals to other clusters that this node has
        successfully completed the DRR procedure.

        Args:
            passport:    The recovered agent's existing passport.
            incident_id: Identifier of the resolved incident.
            now:         Issue timestamp. Defaults to current time.
            ttl_seconds: Short validity window. Default 1 hour.

        Returns:
            A new signed passport carrying the recovery token.
        """
        now = now if now is not None else int(time.time())
        recovered = SemanticPassport(
            model_id=passport.model_id,
            model_version=passport.model_version,
            registry_version=self._version,
            capabilities=passport.capabilities,
            policy_hash=passport.policy_hash,
            issued_at=now,
            expires_at=now + ttl_seconds,
            recovery_token=f"RECOVERY:{incident_id}",
        )
        recovered.sign(self._key)
        return recovered

    def __repr__(self) -> str:
        return f"PassportRegistry(registry_version={self._version!r})"
