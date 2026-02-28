"""
aegis_protocol.transparency_log
-----------------------
Append-only hash-chained transparency log.
"""

import dataclasses
import time
from typing import List, Optional

from aegis_protocol.crypto_utils import sha256_hex


@dataclasses.dataclass
class TransparencyEntry:
    sequence_number: int
    event_type:      str
    model_id:        str
    payload_summary: str
    timestamp:       int
    entry_hash:      str
    prev_hash:       str

    def verify(self) -> bool:
        expected = sha256_hex(
            f"{self.sequence_number}:{self.event_type}:{self.model_id}"
            f":{self.payload_summary}:{self.timestamp}:{self.prev_hash}"
        )
        return self.entry_hash == expected


class TransparencyLog:
    def __init__(self):
        self._entries: List[TransparencyEntry] = []

    def append(self, event_type: str, model_id: str, payload_summary: str,
               timestamp: Optional[int] = None) -> TransparencyEntry:
        if timestamp is None:
            timestamp = int(time.time())
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        entry_hash = sha256_hex(
            f"{seq}:{event_type}:{model_id}:{payload_summary}:{timestamp}:{prev_hash}"
        )
        entry = TransparencyEntry(
            sequence_number=seq,
            event_type=event_type,
            model_id=model_id,
            payload_summary=payload_summary,
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

    def entries_for_model(self, model_id: str) -> List[TransparencyEntry]:
        return [e for e in self._entries if e.model_id == model_id]

    def __len__(self) -> int:
        return len(self._entries)
