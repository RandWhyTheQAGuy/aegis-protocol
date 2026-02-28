"""
aegis_protocol.passport
---------------
PassportRegistry v0.2 — issue, verify (VerifyResult), and recovery tokens.
"""

import dataclasses
import enum
from typing import Optional, List, Dict, Any

from aegis_protocol.crypto_utils import sha256_hex, hmac_sha256, IClock, RealWorldClock


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Capabilities:
    classifier_authority:   bool = False
    classifier_sensitivity: bool = False
    bft_consensus:          bool = False
    entropy_flush:          bool = False

    def to_dict(self) -> Dict[str, bool]:
        return dataclasses.asdict(self)


RECOVERY_CAPS_FLOOR = Capabilities(
    classifier_authority=False,
    classifier_sensitivity=True,
    bft_consensus=False,
    entropy_flush=False,
)

CAPS_FULL = Capabilities(
    classifier_authority=True,
    classifier_sensitivity=True,
    bft_consensus=True,
    entropy_flush=True,
)

CAPS_READ_ONLY = Capabilities(
    classifier_authority=False,
    classifier_sensitivity=True,
    bft_consensus=False,
    entropy_flush=False,
)


# ---------------------------------------------------------------------------
# PassportFlag
# ---------------------------------------------------------------------------

class PassportFlag(enum.Flag):
    NONE      = 0
    RECOVERED = 1


# ---------------------------------------------------------------------------
# SemanticPassport
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class SemanticPassport:
    model_id:       str
    version:        str
    capabilities:   Capabilities
    policy_hash:    str
    issued_at:      int
    ttl_seconds:    int
    signing_key_id: int
    signature:      str
    flags:          PassportFlag = PassportFlag.NONE
    recovery_token: str = ""

    def is_recovered(self) -> bool:
        return bool(self.flags & PassportFlag.RECOVERED)

    def expiry(self) -> int:
        return self.issued_at + self.ttl_seconds


# ---------------------------------------------------------------------------
# VerifyStatus / VerifyResult
# ---------------------------------------------------------------------------

class VerifyStatus(enum.Enum):
    OK       = "OK"
    EXPIRED  = "EXPIRED"
    REVOKED  = "REVOKED"
    INVALID  = "INVALID"
    KEY_UNKNOWN = "KEY_UNKNOWN"


@dataclasses.dataclass
class VerifyResult:
    status:            VerifyStatus
    verified_key_id:   int = 0
    revocation_detail: str = ""

    def ok(self) -> bool:
        return self.status == VerifyStatus.OK


def verify_status_str(status: VerifyStatus) -> str:
    return status.value


# ---------------------------------------------------------------------------
# KeyStore / KeyState
# ---------------------------------------------------------------------------

class KeyState(enum.Enum):
    ACTIVE   = "ACTIVE"
    ROTATING = "ROTATING"
    RETIRED  = "RETIRED"
    PURGED   = "PURGED"


def key_state_str(state: KeyState) -> str:
    return state.value


@dataclasses.dataclass
class KeyMetadata:
    key_id:    int
    state:     KeyState
    active_at: int
    retired_at: Optional[int] = None
    purged_at:  Optional[int] = None


class KeyStore:
    def __init__(self):
        self._keys: Dict[int, Dict[str, Any]] = {}
        self._next_id: int = 1

    def add_key(self, material: str, active_at: int) -> int:
        kid = self._next_id
        self._next_id += 1
        self._keys[kid] = {
            "material": material,
            "state": KeyState.ACTIVE,
            "active_at": active_at,
            "retired_at": None,
            "purged_at": None,
        }
        return kid

    def get_material(self, key_id: int) -> Optional[str]:
        entry = self._keys.get(key_id)
        if entry and entry["state"] != KeyState.PURGED:
            return entry["material"]
        return None

    def key_metadata(self, key_id: int) -> KeyMetadata:
        entry = self._keys[key_id]
        return KeyMetadata(
            key_id=key_id,
            state=entry["state"],
            active_at=entry["active_at"],
            retired_at=entry.get("retired_at"),
            purged_at=entry.get("purged_at"),
        )

    def retire_key(self, key_id: int, at: int) -> None:
        if key_id in self._keys:
            self._keys[key_id]["state"] = KeyState.RETIRED
            self._keys[key_id]["retired_at"] = at

    def purge_expired_keys(self, now: int) -> None:
        for kid, entry in self._keys.items():
            if entry["state"] == KeyState.RETIRED:
                retired_at = entry.get("retired_at") or 0
                if now > retired_at:
                    entry["state"] = KeyState.PURGED
                    entry["purged_at"] = now


# ---------------------------------------------------------------------------
# PassportRegistry
# ---------------------------------------------------------------------------

class PassportRegistry:
    """
    Issues and verifies SemanticPassports.
    Supports key rotation with overlap windows and version-scoped revocation.
    """

    OVERLAP_WINDOW: int = 3600  # seconds old key remains valid after rotation

    def __init__(
        self,
        root_key: str,
        version: str,
        clock: Optional[IClock] = None,
    ):
        self._version = version
        self._clock = clock or RealWorldClock()
        self._key_store = KeyStore()
        self._active_key_id: int = self._key_store.add_key(
            root_key, self._clock.now_unix()
        )
        self._rotating_key_id: Optional[int] = None
        self._rotation_started_at: Optional[int] = None

        # Lazy imports to avoid circular deps
        from aegis_protocol.revocation import RevocationList
        from aegis_protocol.transparency_log import TransparencyLog

        self._revocation_list = RevocationList()
        self._transparency_log = TransparencyLog()

    # ------------------------------------------------------------------
    # Key accessors
    # ------------------------------------------------------------------

    def key_store(self) -> KeyStore:
        return self._key_store

    def transparency_log(self):
        return self._transparency_log

    def revocation_list(self):
        return self._revocation_list

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def issue(
        self,
        model_id: str,
        version: str,
        capabilities: Capabilities,
        policy_hash: str,
        issued_at: int,
        ttl_seconds: int,
    ) -> SemanticPassport:
        key_material = self._key_store.get_material(self._active_key_id)
        payload = (
            f"{model_id}:{version}:{policy_hash}:{issued_at}:{ttl_seconds}"
        )
        signature = hmac_sha256(key_material, payload)
        passport = SemanticPassport(
            model_id=model_id,
            version=version,
            capabilities=capabilities,
            policy_hash=policy_hash,
            issued_at=issued_at,
            ttl_seconds=ttl_seconds,
            signing_key_id=self._active_key_id,
            signature=signature,
        )
        self._transparency_log.append("PASSPORT_ISSUED", model_id,
                                       f"v{version} key_id={self._active_key_id}")
        return passport

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, passport: SemanticPassport, now: int) -> VerifyResult:
        # Expiry check
        if now >= passport.expiry():
            return VerifyResult(status=VerifyStatus.EXPIRED,
                                verified_key_id=passport.signing_key_id)

        # Revocation check
        rev = self._revocation_list.get_revocation(passport.model_id, passport.version)
        if rev is not None:
            return VerifyResult(
                status=VerifyStatus.REVOKED,
                verified_key_id=passport.signing_key_id,
                revocation_detail=rev.get("detail", "REVOKED"),
            )

        # Signature check
        material = self._key_store.get_material(passport.signing_key_id)
        if material is None:
            return VerifyResult(status=VerifyStatus.KEY_UNKNOWN,
                                verified_key_id=passport.signing_key_id)

        payload = (
            f"{passport.model_id}:{passport.version}:{passport.policy_hash}"
            f":{passport.issued_at}:{passport.ttl_seconds}"
        )
        expected = hmac_sha256(material, payload)
        if not _secure_compare(passport.signature, expected):
            return VerifyResult(status=VerifyStatus.INVALID,
                                verified_key_id=passport.signing_key_id)

        return VerifyResult(status=VerifyStatus.OK,
                            verified_key_id=passport.signing_key_id)

    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------

    def rotate_key(self, new_material: str, rotate_at: int, operator: str) -> int:
        new_id = self._key_store.add_key(new_material, rotate_at)
        self._rotating_key_id = self._active_key_id
        self._rotation_started_at = rotate_at
        self._active_key_id = new_id
        self._transparency_log.append("KEY_ROTATION", "system",
                                       f"old_key={self._rotating_key_id} "
                                       f"new_key={new_id} operator={operator}")
        return new_id

    def complete_rotation(self, now: int, passport_max_ttl: int = 86400) -> None:
        if self._rotating_key_id is not None:
            self._key_store.retire_key(self._rotating_key_id, now)
            self._rotating_key_id = None

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke(
        self,
        model_id: str,
        version: str,
        operator: str,
        reason,
        detail: str,
        now: int,
    ) -> str:
        return self._revocation_list.add_revocation(
            model_id=model_id,
            version=version,
            operator=operator,
            reason=reason,
            detail=detail,
            revoked_at=now,
            registry=self,
        )

    # ------------------------------------------------------------------
    # Recovery token
    # ------------------------------------------------------------------

    def issue_recovery_token(
        self,
        original: SemanticPassport,
        incident_id: str,
        issued_at: int,
        ttl_seconds: int,
    ) -> SemanticPassport:
        import dataclasses as dc
        recovery_caps = dc.replace(original.capabilities,
                                   classifier_authority=RECOVERY_CAPS_FLOOR.classifier_authority,
                                   bft_consensus=RECOVERY_CAPS_FLOOR.bft_consensus,
                                   entropy_flush=RECOVERY_CAPS_FLOOR.entropy_flush)
        rec = self.issue(original.model_id, original.version,
                         recovery_caps, original.policy_hash,
                         issued_at, ttl_seconds)
        rec.recovery_token = incident_id
        rec.flags |= PassportFlag.RECOVERED
        return rec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _secure_compare(a: str, b: str) -> bool:
    import hmac as _h
    return _h.compare_digest(a.encode(), b.encode())
