"""
aegis.vault
~~~~~~~~~~~
ColdAuditVault: append-only, cryptographically chained forensic log.

Every policy decision, session event, quarantine, and flush is recorded
here. The chain is verifiable: modifying any historical entry invalidates
all subsequent entries.

Meets EU AI Act Article 12 logging requirements and NIST AI RMF
measurement function traceability requirements when combined with a
durable persistence backend.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterator, List, Optional

from .crypto import sha256_hex
from .exceptions import VaultChainIntegrityError, VaultEntrySchemaError


GENESIS = "GENESIS"

# Valid event types defined in spec/schemas/vault-entry.schema.json
VALID_EVENT_TYPES = frozenset({
    "POLICY_DECISION",
    "SESSION_EVENT",
    "QUARANTINE",
    "FLUSH",
    "PASSPORT_ISSUE",
    "CONSENSUS",
    "HANDSHAKE",
})


@dataclass
class VaultEntry:
    """A single entry in the Cold Audit Vault.

    Fields correspond 1:1 with ``spec/schemas/vault-entry.schema.json``.

    The ``entry_hash`` field is computed and set by :meth:`finalize` —
    do not set it manually.
    """

    entry_id:     str
    prev_hash:    str
    sequence:     int
    timestamp:    int
    event_type:   str
    session_id:   str
    agent_id:     str
    payload_hash: str
    detail:       Dict[str, Any]
    entry_hash:   str = ""

    def canonical(self) -> str:
        """Produce a deterministic string representation for hashing.

        Excludes ``entry_hash`` (which depends on this string).
        Keys are sorted lexicographically.
        """
        body = {
            "agent_id":     self.agent_id,
            "detail":       json.dumps(self.detail, sort_keys=True, separators=(",", ":")),
            "entry_id":     self.entry_id,
            "event_type":   self.event_type,
            "payload_hash": self.payload_hash,
            "prev_hash":    self.prev_hash,
            "sequence":     str(self.sequence),
            "session_id":   self.session_id,
            "timestamp":    str(self.timestamp),
        }
        return "&".join(f"{k}={v}" for k, v in sorted(body.items()))

    def finalize(self) -> "VaultEntry":
        """Compute and set ``entry_hash``. Call before storing the entry.

        Returns:
            Self, for chaining.
        """
        self.entry_hash = sha256_hex(self.canonical())
        return self

    def verify(self) -> bool:
        """Return True if ``entry_hash`` matches the canonical body."""
        return sha256_hex(self.canonical()) == self.entry_hash

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "entry_id":     self.entry_id,
            "prev_hash":    self.prev_hash,
            "sequence":     self.sequence,
            "timestamp":    self.timestamp,
            "event_type":   self.event_type,
            "session_id":   self.session_id,
            "agent_id":     self.agent_id,
            "payload_hash": self.payload_hash,
            "detail":       self.detail,
            "entry_hash":   self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultEntry":
        return cls(
            entry_id=data["entry_id"],
            prev_hash=data["prev_hash"],
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            payload_hash=data.get("payload_hash", ""),
            detail=data.get("detail", {}),
            entry_hash=data.get("entry_hash", ""),
        )

    def __repr__(self) -> str:
        return (
            f"VaultEntry(seq={self.sequence}, "
            f"type={self.event_type!r}, "
            f"agent={self.agent_id!r})"
        )


class ColdAuditVault:
    """Append-only, cryptographically chained audit log.

    Each entry's ``entry_id`` is derived from the previous entry's
    ``entry_hash``, making tampering with any historical entry detectable
    by recomputing the chain from genesis.

    The vault is in-memory by default. For persistence, call :meth:`to_jsonl`
    to export and :meth:`from_jsonl` to reload. For production deployments,
    use a write-once storage backend (e.g., S3 Object Lock, Trillian).

    Example::

        vault = ColdAuditVault()

        # Record a policy decision
        vault.append(
            event_type="POLICY_DECISION",
            session_id=session.session_id,
            agent_id="agent-alpha",
            payload_hash=score.payload_hash,
            detail={"action": "DENY", "rule_id": "deny-low-auth-high-sens"},
        )

        # Record a flush event from the session callback
        def on_flush(session_id, incident_id, tainted):
            vault.append(
                event_type="FLUSH",
                session_id=session_id,
                agent_id="agent-alpha",
                payload_hash="",
                detail={"incident_id": incident_id, "tainted": tainted},
            )

        # Verify chain integrity
        vault.verify_chain()   # raises VaultChainIntegrityError if tampered
        print(f"Vault entries: {len(vault)}")
    """

    def __init__(self) -> None:
        self._entries: List[VaultEntry] = []

    # ------------------------------------------------------------------
    # Appending entries
    # ------------------------------------------------------------------

    def append(
        self,
        event_type: str,
        session_id: str,
        agent_id: str,
        payload_hash: str,
        detail: Dict[str, Any],
        timestamp: Optional[int] = None,
    ) -> str:
        """Append a new entry to the vault.

        Args:
            event_type:   One of the VALID_EVENT_TYPES constants.
            session_id:   Session identifier.
            agent_id:     model_id of the agent generating this event.
            payload_hash: SHA-256 of the associated payload, or '' if N/A.
            detail:       Event-specific structured data (JSON-serializable).
            timestamp:    Unix timestamp. Defaults to current time.

        Returns:
            The ``entry_hash`` of the appended entry.

        Raises:
            VaultEntrySchemaError: If event_type is not a valid type.
        """
        if event_type not in VALID_EVENT_TYPES:
            raise VaultEntrySchemaError(
                f"Invalid event_type {event_type!r}. "
                f"Must be one of: {sorted(VALID_EVENT_TYPES)}"
            )

        timestamp = timestamp if timestamp is not None else int(time.time())
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS
        sequence  = len(self._entries)
        entry_id  = sha256_hex(prev_hash + str(sequence))

        entry = VaultEntry(
            entry_id=entry_id,
            prev_hash=prev_hash,
            sequence=sequence,
            timestamp=timestamp,
            event_type=event_type,
            session_id=session_id,
            agent_id=agent_id,
            payload_hash=payload_hash,
            detail=detail,
        ).finalize()

        self._entries.append(entry)
        return entry.entry_hash

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> None:
        """Verify the integrity of the entire vault chain.

        Re-computes each entry's hash and confirms the chain is unbroken.

        Raises:
            VaultChainIntegrityError: If any entry fails verification or
                                      the chain linkage is broken.
        """
        expected_prev = GENESIS
        for i, entry in enumerate(self._entries):
            if not entry.verify():
                raise VaultChainIntegrityError(
                    i, f"entry_hash mismatch at sequence {i}"
                )
            if entry.prev_hash != expected_prev:
                raise VaultChainIntegrityError(
                    i,
                    f"prev_hash mismatch at sequence {i}: "
                    f"expected {expected_prev[:16]}..., "
                    f"got {entry.prev_hash[:16]}..."
                )
            if entry.sequence != i:
                raise VaultChainIntegrityError(
                    i, f"sequence number mismatch: expected {i}, got {entry.sequence}"
                )
            expected_prev = entry.entry_hash

    def is_valid(self) -> bool:
        """Return True if the chain is intact; False otherwise.

        Unlike :meth:`verify_chain`, this does not raise on failure.
        """
        try:
            self.verify_chain()
            return True
        except VaultChainIntegrityError:
            return False

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[VaultEntry]:
        return iter(self._entries)

    def __getitem__(self, index: int) -> VaultEntry:
        return self._entries[index]

    def by_session(self, session_id: str) -> List[VaultEntry]:
        """Return all entries for a given session_id."""
        return [e for e in self._entries if e.session_id == session_id]

    def by_event_type(self, event_type: str) -> List[VaultEntry]:
        """Return all entries of a given event_type."""
        return [e for e in self._entries if e.event_type == event_type]

    def by_agent(self, agent_id: str) -> List[VaultEntry]:
        """Return all entries generated by a given agent_id."""
        return [e for e in self._entries if e.agent_id == agent_id]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_jsonl(self) -> str:
        """Serialize the vault to newline-delimited JSON (JSONL).

        Each line is a JSON-encoded :class:`VaultEntry`. Suitable for
        streaming to a write-once storage backend.

        Returns:
            JSONL string.
        """
        return "\n".join(
            json.dumps(entry.to_dict(), separators=(",", ":"))
            for entry in self._entries
        )

    @classmethod
    def from_jsonl(cls, data: str, verify: bool = True) -> "ColdAuditVault":
        """Reconstruct a vault from JSONL data.

        Args:
            data:   JSONL string (one entry per line).
            verify: If True, call :meth:`verify_chain` after loading.
                    Default True.

        Returns:
            A :class:`ColdAuditVault` instance.

        Raises:
            VaultChainIntegrityError: If verify=True and the chain is broken.
        """
        vault = cls()
        for line in data.strip().splitlines():
            if not line.strip():
                continue
            entry = VaultEntry.from_dict(json.loads(line))
            vault._entries.append(entry)
        if verify:
            vault.verify_chain()
        return vault

    def __repr__(self) -> str:
        return f"ColdAuditVault(entries={len(self._entries)}, valid={self.is_valid()})"
