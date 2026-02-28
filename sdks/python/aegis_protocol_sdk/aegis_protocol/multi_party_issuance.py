"""
aegis_protocol.multi_party_issuance
~~~~~~~~~~~~~~~~~~~~~~~~~~~
MultiPartyIssuer: quorum-gated passport issuance.

Security properties:
  - Mutual exclusivity of countersign and reject per signer (resolves SEC-011).
  - Each rejection is logged to the transparency log with signer identity.
  - Rejection threshold = N - M + 1 (N signers, M threshold).
  - Stale proposals expire after proposal_ttl_seconds.
"""

import enum
from dataclasses import dataclass, field
from typing import Optional

from .crypto_utils import sha256_hex, hmac_sha256_hex, generate_nonce
from .passport import Capabilities, SemanticPassport, PassportFlag, _TransparencyLog
from .exceptions import SecurityViolation


class QuorumState(enum.Enum):
    PENDING   = "PENDING"
    FINALIZED = "FINALIZED"
    REJECTED  = "REJECTED"
    EXPIRED   = "EXPIRED"


@dataclass
class _Proposal:
    proposal_id:     str
    proposer:        str
    model_id:        str
    version:         str
    capabilities:    Capabilities
    policy_hash:     str
    proposed_at:     int
    ttl_seconds:     int
    state:           QuorumState = QuorumState.PENDING
    countersigned_by: set = field(default_factory=set)
    rejected_by:      set = field(default_factory=set)
    partial_sigs:     dict = field(default_factory=dict)   # signer_id -> sig_hex
    finalized_passport: Optional[SemanticPassport] = None


class MultiPartyIssuer:
    """
    Quorum-gated passport issuance requiring M-of-N signers.

    Usage:
        mpi = MultiPartyIssuer(["a", "b", "c"], threshold=2, ...)
        pid = mpi.propose("a", root_a, "agent-x", "1.0.0", caps, ph, now, ttl)
        mpi.countersign("b", root_b, pid, now)
        pq = mpi.get_finalized_passport(pid)
    """

    def __init__(
        self,
        signers: list[str],
        threshold: int,
        registry_version: str,
        transparency_log: _TransparencyLog,
        proposal_ttl_seconds: int = 300,
    ) -> None:
        if threshold < 1 or threshold > len(signers):
            raise ValueError("threshold must be between 1 and len(signers)")
        self._signers = list(signers)
        self._threshold = threshold
        self._reg_version = registry_version
        self._tlog = transparency_log
        self._proposal_ttl = proposal_ttl_seconds
        self._proposals: dict[str, _Proposal] = {}

    # ── Internal ─────────────────────────────────────────────────────────────

    def _reject_threshold(self) -> int:
        return len(self._signers) - self._threshold + 1

    def _make_partial_sig(self, signer_id: str, root_key: str,
                           proposal: _Proposal) -> str:
        return hmac_sha256_hex(
            root_key,
            f"{proposal.proposal_id}:{signer_id}:{proposal.model_id}"
            f":{proposal.version}:{proposal.proposed_at}"
        )

    def _build_composite_sig(self, proposal: _Proposal) -> str:
        combined = ":".join(
            f"{sid}={sig}"
            for sid, sig in sorted(proposal.partial_sigs.items())
        )
        return sha256_hex(combined)

    # ── Public API ────────────────────────────────────────────────────────────

    def propose(
        self,
        proposer_id: str,
        root_key: str,
        model_id: str,
        version: str,
        capabilities: Capabilities,
        policy_hash: str,
        proposed_at: int,
        ttl_seconds: int,
    ) -> str:
        if proposer_id not in self._signers:
            raise SecurityViolation(f"propose: {proposer_id!r} is not a registered signer")

        pid = generate_nonce(16)
        proposal = _Proposal(
            proposal_id=pid,
            proposer=proposer_id,
            model_id=model_id,
            version=version,
            capabilities=capabilities.copy(),
            policy_hash=policy_hash,
            proposed_at=proposed_at,
            ttl_seconds=ttl_seconds,
        )

        # Proposer automatically adds their partial signature
        sig = self._make_partial_sig(proposer_id, root_key, proposal)
        proposal.partial_sigs[proposer_id] = sig
        proposal.countersigned_by.add(proposer_id)

        self._proposals[pid] = proposal
        self._tlog.append("PROPOSAL_CREATED", model_id, proposer_id, pid[:16], proposed_at)
        return pid

    def countersign(
        self,
        signer_id: str,
        root_key: str,
        proposal_id: str,
        now: int,
    ) -> bool:
        """
        Add a countersignature.  Returns True when the quorum threshold is met
        and the proposal transitions to FINALIZED.
        """
        if signer_id not in self._signers:
            raise SecurityViolation(f"countersign: {signer_id!r} is not a registered signer")

        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"countersign: unknown proposal {proposal_id!r}")
        if proposal.state != QuorumState.PENDING:
            raise SecurityViolation(
                f"countersign: proposal {proposal_id!r} is {proposal.state.value}, not PENDING")

        # Resolves SEC-011: mutual exclusivity
        if signer_id in proposal.rejected_by:
            raise SecurityViolation(
                f"Signer {signer_id!r} has already rejected proposal "
                f"{proposal_id!r} and cannot also countersign it"
            )

        sig = self._make_partial_sig(signer_id, root_key, proposal)
        proposal.partial_sigs[signer_id] = sig
        proposal.countersigned_by.add(signer_id)

        if len(proposal.countersigned_by) >= self._threshold:
            self._finalize(proposal, now)

        return proposal.state == QuorumState.FINALIZED

    def _finalize(self, proposal: _Proposal, now: int) -> None:
        composite_sig = self._build_composite_sig(proposal)
        passport = SemanticPassport(
            model_id=proposal.model_id,
            version=proposal.version,
            signing_key_id=0,
            signing_key_material="",
            policy_hash=proposal.policy_hash,
            capabilities=proposal.capabilities.copy(),
            issued_at=proposal.proposed_at,
            expires_at=proposal.proposed_at + proposal.ttl_seconds,
            signature=composite_sig,
            flags=0,
        )
        proposal.finalized_passport = passport
        proposal.state = QuorumState.FINALIZED
        self._tlog.append("PROPOSAL_FINALIZED", proposal.model_id,
                          "quorum", proposal.proposal_id[:16], now)

    def reject(self, signer_id: str, proposal_id: str, now: int) -> bool:
        """
        Record a rejection.  Returns True when the rejection threshold is met
        and the proposal transitions to REJECTED.
        """
        if signer_id not in self._signers:
            raise SecurityViolation(f"reject: {signer_id!r} is not a registered signer")

        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"reject: unknown proposal {proposal_id!r}")
        if proposal.state != QuorumState.PENDING:
            raise SecurityViolation(
                f"reject: proposal {proposal_id!r} is {proposal.state.value}, not PENDING")

        # Resolves SEC-011: mutual exclusivity
        if signer_id in proposal.countersigned_by:
            raise SecurityViolation(
                f"Signer {signer_id!r} has already countersigned proposal "
                f"{proposal_id!r} and cannot also reject it"
            )

        proposal.rejected_by.add(signer_id)
        self._tlog.append("PROPOSAL_REJECTION", proposal.model_id,
                          signer_id, f"threshold={self._reject_threshold()}", now)

        if len(proposal.rejected_by) >= self._reject_threshold():
            proposal.state = QuorumState.REJECTED

        return proposal.state == QuorumState.REJECTED

    def get_proposal(self, proposal_id: str) -> _Proposal:
        p = self._proposals.get(proposal_id)
        if p is None:
            raise KeyError(f"get_proposal: unknown proposal {proposal_id!r}")
        return p

    def get_finalized_passport(self, proposal_id: str) -> SemanticPassport:
        p = self.get_proposal(proposal_id)
        if p.state != QuorumState.FINALIZED or p.finalized_passport is None:
            raise SecurityViolation(
                f"get_finalized_passport: proposal {proposal_id!r} is not FINALIZED")
        return p.finalized_passport

    def verify_quorum_passport(
        self,
        passport: SemanticPassport,
        root_key: str,
        now: int,
    ) -> bool:
        """Verify a quorum passport's composite signature."""
        # Find the proposal that produced this passport
        for proposal in self._proposals.values():
            if (proposal.finalized_passport is not None and
                    proposal.finalized_passport.model_id == passport.model_id and
                    proposal.finalized_passport.version == passport.version):
                expected = self._build_composite_sig(proposal)
                import hmac as _hmac
                return _hmac.compare_digest(expected, passport.signature)
        return False

    def expire_stale_proposals(self, now: int) -> int:
        """
        Expire all PENDING proposals whose TTL has elapsed.  Returns count.

        The governing TTL is the MPI-level proposal_ttl_seconds set at construction.
        Per-proposal ttl_seconds (the passport validity period) is not used here —
        a proposal must be ratified within the MPI window or it is discarded.
        """
        expired = 0
        for proposal in self._proposals.values():
            if proposal.state == QuorumState.PENDING:
                if now > proposal.proposed_at + self._proposal_ttl:
                    proposal.state = QuorumState.EXPIRED
                    expired += 1
        return expired
