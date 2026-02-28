"""
aegis_protocol.revocation
-----------------
RevocationList with full-model and version-scoped revocation.
"""

import enum
from typing import Optional, Dict, Any

from aegis_protocol.crypto_utils import sha256_hex, hmac_sha256


class RevocationReason(enum.Enum):
    KEY_COMPROMISE       = "KEY_COMPROMISE"
    VERSION_SUPERSEDED   = "VERSION_SUPERSEDED"
    POLICY_VIOLATION     = "POLICY_VIOLATION"
    ADMINISTRATIVE       = "ADMINISTRATIVE"


class RevocationList:
    def __init__(self):
        # key: (model_id, version_or_"") -> record dict
        self._records: Dict[tuple, Dict[str, Any]] = {}

    def add_revocation(
        self,
        model_id: str,
        version: str,
        operator: str,
        reason: RevocationReason,
        detail: str,
        revoked_at: int,
        registry=None,
    ) -> str:
        key = (model_id, version)
        token_material = f"{model_id}:{version}:{reason.value}:{revoked_at}"
        # Sign with registry active key if available
        if registry is not None:
            key_material = registry.key_store().get_material(
                registry._active_key_id
            )
            token = hmac_sha256(key_material, token_material)
        else:
            token = sha256_hex(token_material)

        record = {
            "model_id": model_id,
            "version": version,
            "operator": operator,
            "reason": reason,
            "detail": detail,
            "revoked_at": revoked_at,
            "token": token,
        }
        self._records[key] = record
        return token

    def get_revocation(self, model_id: str, version: str) -> Optional[Dict[str, Any]]:
        # Check full-model revocation first (version="")
        full_rec = self._records.get((model_id, ""))
        if full_rec is not None:
            return full_rec
        # Check version-scoped
        ver_rec = self._records.get((model_id, version))
        return ver_rec

    def is_revoked(self, model_id: str, version: str) -> bool:
        return self.get_revocation(model_id, version) is not None

    def verify_revocation_token(self, record: Dict[str, Any]) -> bool:
        """Basic structural verification — token must be non-empty."""
        return bool(record.get("token"))
