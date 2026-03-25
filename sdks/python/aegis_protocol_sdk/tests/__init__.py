"""
Aegis Protocol — Semantic Agent Security SDK
=====================================
Python port of the C++ Aegis Protocol reference implementation.

Quick start::

    from aegis_protocol import PassportRegistry, Capabilities, CAPS_FULL
    from aegis_protocol.crypto_utils import TestClock

    clock = TestClock(1_740_000_000)
    registry = PassportRegistry("my-32-byte-root-key-padding!!!!!", "0.1.0", clock)
    passport = registry.issue("my-agent", "1.0.0", CAPS_FULL, "policy-hash", clock.now_unix(), 86400)
    result = registry.verify(passport, clock.now_unix())
    assert result.ok()
"""

from aegis_protocol.crypto_utils import (
    sha256_hex,
    hmac_sha256,
    generate_nonce,
    derive_direction_key,
    ephemeral_dh_exchange,
    compute_shared_secret,
    IClock,
    RealWorldClock,
    TestClock,
    validate_timestamp,
    MAX_CLOCK_SKEW_SECONDS,
)

from aegis_protocol.exceptions import (
    AegisProtocolError,
    SecurityViolation,
    PassportError,
    RevocationError,
    HandshakeError,
    PolicyError,
    ConsensusError,
    VaultError,
    QuorumError,
)

from aegis_protocol.passport import (
    Capabilities,
    CAPS_FULL,
    CAPS_READ_ONLY,
    RECOVERY_CAPS_FLOOR,
    PassportFlag,
    SemanticPassport,
    VerifyStatus,
    VerifyResult,
    verify_status_str,
    KeyState,
    KeyMetadata,
    KeyStore,
    KeyStore as key_state_str,
    PassportRegistry,
)
from aegis_protocol.passport import key_state_str  # noqa: F811 — re-export

from aegis_protocol.revocation import RevocationReason, RevocationList

from aegis_protocol.transparency_log import TransparencyEntry, TransparencyLog

from aegis_protocol.multi_party import QuorumState, Proposal, MultiPartyIssuer

from aegis_protocol.handshake import (
    TransportBindingType,
    TransportIdentity,
    SessionContext,
    NonceCache,
    HelloMessage,
    AckMessage,
    ConfirmMessage,
    AckResult,
    ProcessAckResult,
    ConfirmResult,
    HandshakeValidator,
)

from aegis_protocol.classifier import SemanticScore, make_stub_backend, SemanticClassifier

from aegis_protocol.policy import (
    PolicyAction,
    action_str,
    LogLevel,
    TrustCriteria,
    ScopeCriteria,
    PolicyRule,
    CompatibilityManifest,
    PolicyDecision,
    PolicyEngine,
    RECOVERED_AGENT_CONFIDENCE_FLOOR,
)

from aegis_protocol.session import (
    SessionState,
    state_str,
    Session,
)

from aegis_protocol.consensus import AgentScore, ConsensusResult, BFTConsensusEngine

from aegis_protocol.vault import VaultEntry, ColdAuditVault

from aegis_protocol.incident import IncidentId, make_incident_id

__all__ = [
    # crypto
    "sha256_hex", "hmac_sha256", "generate_nonce", "derive_direction_key",
    "ephemeral_dh_exchange", "compute_shared_secret",
    "IClock", "RealWorldClock", "TestClock", "validate_timestamp",
    "MAX_CLOCK_SKEW_SECONDS",
    # exceptions
    "aegis_protocolError", "SecurityViolation", "PassportError", "RevocationError",
    "HandshakeError", "PolicyError", "ConsensusError", "VaultError", "QuorumError",
    # passport
    "Capabilities", "CAPS_FULL", "CAPS_READ_ONLY", "RECOVERY_CAPS_FLOOR",
    "PassportFlag", "SemanticPassport", "VerifyStatus", "VerifyResult",
    "verify_status_str", "KeyState", "key_state_str", "KeyMetadata",
    "KeyStore", "PassportRegistry",
    # revocation
    "RevocationReason", "RevocationList",
    # transparency log
    "TransparencyEntry", "TransparencyLog",
    # multi-party
    "QuorumState", "Proposal", "MultiPartyIssuer",
    # handshake
    "TransportBindingType", "TransportIdentity", "SessionContext",
    "NonceCache", "HelloMessage", "AckMessage", "ConfirmMessage",
    "AckResult", "ProcessAckResult", "ConfirmResult", "HandshakeValidator",
    # classifier
    "SemanticScore", "make_stub_backend", "SemanticClassifier",
    # policy
    "PolicyAction", "action_str", "LogLevel", "TrustCriteria", "ScopeCriteria",
    "PolicyRule", "CompatibilityManifest", "PolicyDecision", "PolicyEngine",
    "RECOVERED_AGENT_CONFIDENCE_FLOOR",
    # session
    "SessionState", "state_str", "Session",
    # consensus
    "AgentScore", "ConsensusResult", "BFTConsensusEngine",
    # vault
    "VaultEntry", "ColdAuditVault",
    # incident
    "IncidentId", "make_incident_id",
]

__version__ = "0.1.0"