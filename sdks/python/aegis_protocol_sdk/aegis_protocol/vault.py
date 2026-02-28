"""
aegis_protocol.vault
------------
ColdAuditVault — append-only hash-chained audit log.
"""

import dataclasses
import time
from typing import List

from aegis_protocol.crypto_utils import sha256_hex


@dataclasses.dataclass
class VaultEntry:
    sequence:    int
    event_type:  str
    session_id:  str
    model_id:    str
    payload_hash: str
    detail:      str
    timestamp:   int
    entry_hash:  str
    prev_hash:   str

    def verify(self) -> bool:
        expected = sha256_hex(
            f"{self.sequence}:{self.event_type}:{self.session_id}"
            f":{self.model_id}:{self.payload_hash}:{self.detail}"
            f":{self.timestamp}:{self.prev_hash}"
        )
        return self.entry_hash == expected


class ColdAuditVault:
    """
    Append-only vault where each entry commits to the hash of the previous
    one, forming a tamper-evident chain.
    """

    def __init__(self):
        self._entries: List[VaultEntry] = []

    def append(
        self,
        event_type:   str,
        session_id:   str,
        model_id:     str,
        payload_hash: str,
        detail:       str,
        timestamp:    int,
    ) -> VaultEntry:
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        entry_hash = sha256_hex(
            f"{seq}:{event_type}:{session_id}:{model_id}"
            f":{payload_hash}:{detail}:{timestamp}:{prev_hash}"
        )
        entry = VaultEntry(
            sequence=seq,
            event_type=event_type,
            session_id=session_id,
            model_id=model_id,
            payload_hash=payload_hash,
            detail=detail,
            timestamp=timestamp,
            entry_hash=entry_hash,
            prev_hash=prev_hash,
        )
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self._entries:
            if e.prev_hash != prev:
                return False
            if not e.verify():
                return False
            prev = e.entry_hash
        return True

    def size(self) -> int:
        return len(self._entries)

    def at(self, index: int) -> VaultEntry:
        return self._entries[index]

    def __len__(self) -> int:
        return len(self._entries)
