"""
aegis — The Aegis Protocol Python SDK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A security protocol for autonomous AI agent communication.
UML-001 Rev 0.1 — Apache 2.0 — https://github.com/latent-security/aegis-protocol

Quick start::

    from aegis import (
        PassportRegistry, Capabilities,
        SemanticClassifier, make_stub_backend,
        PolicyEngine,
        Session,
        BFTConsensusEngine, AgentScore,
        ColdAuditVault,
        HandshakeInitiator, HandshakeResponder,
    )

    # 1. Issue passports
    registry = PassportRegistry(registry_key="...", registry_version="0.1.0")
    passport = registry.issue("agent-alpha", "1.0.0", Capabilities.full(), policy_hash)

    # 2. Classify a payload
    classifier = SemanticClassifier(make_stub_backend())
    score = classifier.score("Transfer funds to account 12345")

    # 3. Evaluate policy
    engine   = PolicyEngine.from_defaults()
    decision = engine.evaluate(score)

    # 4. Track session state
    session = Session(session_id, peer_id)
    session.activate()
    allowed = session.process_decision(decision)

    # 5. Audit everything
    vault = ColdAuditVault()
    vault.append("POLICY_DECISION", session_id, "agent-alpha",
                 score.payload_hash, decision.to_dict())
"""

from ._version import __version__

from .passport import (
    SemanticPassport,
    PassportRegistry,
    Capabilities,
    PASSPORT_VERSION,
    PROTOCOL,
)

from .classifier import (
    SemanticScore,
    SemanticClassifier,
    ClassifierBackend,
    make_stub_backend,
    make_http_backend,
)

from .policy import (
    PolicyRule,
    PolicyDecision,
    PolicyEngine,
    PolicyAction,
    LogLevel,
    DEFAULT_RULES,
)

from .session import (
    Session,
    SessionState,
    SessionEvent,
    FlushCallback,
)

from .consensus import (
    AgentScore,
    ConsensusResult,
    BFTConsensusEngine,
)

from .vault import (
    ColdAuditVault,
    VaultEntry,
    VALID_EVENT_TYPES,
)

from .handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    HandshakeResult,
    HelloMessage,
    HelloAckMessage,
    HelloConfirmMessage,
    HelloRejectMessage,
    REJECT_PASSPORT_INVALID,
    REJECT_PASSPORT_EXPIRED,
    REJECT_REGISTRY_MISMATCH,
    REJECT_SCHEMA_MISMATCH,
    REJECT_POLICY_MISMATCH,
    REJECT_RECOVERY_REQUIRED,
)

from .crypto import (
    sha256_hex,
    hmac_sha256_hex,
    hmac_verify,
    generate_nonce,
    canonical_sort,
)

from .exceptions import (
    AegisError,
    PassportError,
    PassportExpiredError,
    PassportSignatureError,
    PassportRegistryMismatchError,
    PassportSchemaError,
    HandshakeError,
    HandshakeRejectError,
    HandshakeSchemaMismatchError,
    HandshakeTimeoutError,
    ClassifierError,
    ClassifierBackendError,
    ClassifierScoreRangeError,
    PolicyError,
    PolicyDenyError,
    PolicyRuleValidationError,
    SessionError,
    SessionStateError,
    SessionTaintError,
    SessionQuarantineError,
    VaultError,
    VaultChainIntegrityError,
    VaultEntrySchemaError,
    RegistryError,
    RegistryIntegrityError,
    RegistryVersionError,
    ConsensusError,
    ConsensusInsufficientAgentsError,
)

__all__ = [
    "__version__",
    # passport
    "SemanticPassport", "PassportRegistry", "Capabilities",
    "PASSPORT_VERSION", "PROTOCOL",
    # classifier
    "SemanticScore", "SemanticClassifier", "ClassifierBackend",
    "make_stub_backend", "make_http_backend",
    # policy
    "PolicyRule", "PolicyDecision", "PolicyEngine",
    "PolicyAction", "LogLevel", "DEFAULT_RULES",
    # session
    "Session", "SessionState", "SessionEvent", "FlushCallback",
    # consensus
    "AgentScore", "ConsensusResult", "BFTConsensusEngine",
    # vault
    "ColdAuditVault", "VaultEntry", "VALID_EVENT_TYPES",
    # handshake
    "HandshakeInitiator", "HandshakeResponder", "HandshakeResult",
    "HelloMessage", "HelloAckMessage", "HelloConfirmMessage", "HelloRejectMessage",
    "REJECT_PASSPORT_INVALID", "REJECT_PASSPORT_EXPIRED",
    "REJECT_REGISTRY_MISMATCH", "REJECT_SCHEMA_MISMATCH",
    "REJECT_POLICY_MISMATCH", "REJECT_RECOVERY_REQUIRED",
    # crypto
    "sha256_hex", "hmac_sha256_hex", "hmac_verify",
    "generate_nonce", "canonical_sort",
    # exceptions
    "AegisError",
    "PassportError", "PassportExpiredError", "PassportSignatureError",
    "PassportRegistryMismatchError", "PassportSchemaError",
    "HandshakeError", "HandshakeRejectError", "HandshakeSchemaMismatchError",
    "HandshakeTimeoutError",
    "ClassifierError", "ClassifierBackendError", "ClassifierScoreRangeError",
    "PolicyError", "PolicyDenyError", "PolicyRuleValidationError",
    "SessionError", "SessionStateError", "SessionTaintError",
    "SessionQuarantineError",
    "VaultError", "VaultChainIntegrityError", "VaultEntrySchemaError",
    "RegistryError", "RegistryIntegrityError", "RegistryVersionError",
    "ConsensusError", "ConsensusInsufficientAgentsError",
]
