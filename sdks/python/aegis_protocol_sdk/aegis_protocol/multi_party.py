"""
aegis_protocol.multi_party
------------------
MultiPartyIssuer — 2-of-N quorum, rejection, expiry, composite signatures.
"""

import dataclasses
import enum
import uuid
from typing import Dict, List, Optional, Any

from aegis_protocol.crypto_utils import sha256_hex, hmac_sha256
from aegis_protocol.passport import Capabilities, SemanticPassport


class QuorumState(enum.Enum):
    PENDING   = "PENDING"
    FINALIZED = "FINALIZED"
    REJECTED  = "REJECTED"
    EXPIRED   = "EXPIRED"


@dataclasses.dataclass
class Proposal:
    proposal_id:   str
    proposer:      str
    model_id:      str
    version:       str
    capabilities:  Capabilities
    policy_hash:   str
    issued_at:     int
    ttl_seconds:   int
    state:         QuorumState
    partial_sigs:  Dict[str, str]  # signer_id -> sig
    rejections:    List[str]       # list of signer_ids
    created_at:    int
    finalized_passport: Optional[SemanticPassport] = None


class MultiPartyIssuer:
    """
    Manages multi-party (threshold-signature) passport issuance.
    """

    def __init__(
        self,
        signers: List[str],
        threshold: int,
        registry_version: str,
        transparency_log,
        proposal_ttl_seconds: int = 300,
    ):
        self._signers = list(signers)
        self._threshold = threshold
        self._reg_version = registry_version
        self._tlog = transparency_log
        self._proposal_ttl = proposal_ttl_seconds
        self._proposals: Dict[str, Proposal] = {}

    # ------------------------------------------------------------------
    # Propose
    # ------------------------------------------------------------------

    def propose(
        self,
        proposer: str,
        root_key: str,
        model_id: str,
        version: str,
        capabilities: Capabilities,
        policy_hash: str,
        issued_at: int,
        ttl_seconds: int,
    ) -> str:
        self._require_signer(proposer)
        pid = str(uuid.uuid4())
        sig = self._sign(root_key, pid, model_id, version, issued_at)
        prop = Proposal(
            proposal_id=pid,
            proposer=proposer,
            model_id=model_id,
            version=version,
            capabilities=capabilities,
            policy_hash=policy_hash,
            issued_at=issued_at,
            ttl_seconds=ttl_seconds,
            state=QuorumState.PENDING,
            partial_sigs={proposer: sig},
            rejections=[],
            created_at=issued_at,
        )
        self._proposals[pid] = prop
        self._tlog.append("MPI_PROPOSED", model_id, f"pid={pid[:16]} proposer={proposer}")
        return pid

    # ------------------------------------------------------------------
    # Countersign
    # ------------------------------------------------------------------

    def countersign(self, signer: str, root_key: str, proposal_id: str, now: int) -> bool:
        self._require_signer(signer)
        prop = self._get_pending(proposal_id)
        if signer in prop.partial_sigs:
            return False  # already signed
        sig = self._sign(root_key, proposal_id, prop.model_id, prop.version, prop.issued_at)
        prop.partial_sigs[signer] = sig
        if len(prop.partial_sigs) >= self._threshold:
            self._finalize(prop)
            return True
        return False

    # ------------------------------------------------------------------
    # Reject
    # ------------------------------------------------------------------

    def reject(self, signer: str, proposal_id: str, now: int) -> None:
        self._require_signer(signer)
        prop = self._get_pending(proposal_id)
        if signer not in prop.rejections:
            prop.rejections.append(signer)
        # N - threshold + 1 rejections kills the proposal
        kill_threshold = len(self._signers) - self._threshold + 1
        if len(prop.rejections) >= kill_threshold:
            prop.state = QuorumState.REJECTED
            self._tlog.append("MPI_REJECTED", prop.model_id, f"pid={proposal_id[:16]}")

    # ------------------------------------------------------------------
    # Expire stale proposals
    # ------------------------------------------------------------------

    def expire_stale_proposals(self, now: int) -> None:
        for prop in self._proposals.values():
            if prop.state == QuorumState.PENDING:
                if now > prop.created_at + self._proposal_ttl:
                    prop.state = QuorumState.EXPIRED
                    self._tlog.append("MPI_EXPIRED", prop.model_id,
                                       f"pid={prop.proposal_id[:16]}")

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_proposal(self, proposal_id: str) -> Proposal:
        return self._proposals[proposal_id]

    def get_finalized_passport(self, proposal_id: str) -> SemanticPassport:
        prop = self._proposals[proposal_id]
        if prop.state != QuorumState.FINALIZED:
            from aegis_protocol.exceptions import QuorumError
            raise QuorumError(f"Proposal {proposal_id} is not FINALIZED")
        return prop.finalized_passport

    def verify_quorum_passport(self, passport: SemanticPassport, root_key: str, now: int) -> bool:
        return bool(passport.signature) and now < passport.expiry()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require_signer(self, signer: str) -> None:
        if signer not in self._signers:
            from aegis_protocol.exceptions import QuorumError
            raise QuorumError(f"Unknown signer: {signer}")

    def _get_pending(self, proposal_id: str) -> Proposal:
        prop = self._proposals.get(proposal_id)
        if prop is None:
            from aegis_protocol.exceptions import QuorumError
            raise QuorumError(f"Unknown proposal: {proposal_id}")
        if prop.state != QuorumState.PENDING:
            from aegis_protocol.exceptions import QuorumError
            raise QuorumError(f"Proposal {proposal_id} is not PENDING (state={prop.state})")
        return prop

    def _sign(self, root_key: str, pid: str, model_id: str, version: str, issued_at: int) -> str:
        payload = f"{pid}:{model_id}:{version}:{issued_at}"
        return hmac_sha256(root_key, payload)

    def _finalize(self, prop: Proposal) -> None:
        composite_sig = sha256_hex(":".join(sorted(prop.partial_sigs.values())))
        import dataclasses as dc
        passport = SemanticPassport(
            model_id=prop.model_id,
            version=prop.version,
            capabilities=prop.capabilities,
            policy_hash=prop.policy_hash,
            issued_at=prop.issued_at,
            ttl_seconds=prop.ttl_seconds,
            signing_key_id=0,
            signature=composite_sig,
        )
        prop.state = QuorumState.FINALIZED
        prop.finalized_passport = passport
        self._tlog.append("MPI_FINALIZED", prop.model_id,
                           f"pid={prop.proposal_id[:16]} sigs={len(prop.partial_sigs)}")
