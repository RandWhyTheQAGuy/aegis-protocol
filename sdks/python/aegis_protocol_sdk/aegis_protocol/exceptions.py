"""aegis_protocol exception hierarchy."""

class AegisProtocolError(Exception):
    """Base exception for all AegisProtocol SDK errors."""


class SecurityViolation(AegisProtocolError):
    """Raised when a security constraint is violated."""


class PassportError(AegisProtocolError):
    """Raised for passport-related errors."""


class RevocationError(AegisProtocolError):
    """Raised when a revocation operation fails."""


class HandshakeError(AegisProtocolError):
    """Raised for handshake failures."""


class PolicyError(AegisProtocolError):
    """Raised for policy evaluation errors."""


class ConsensusError(AegisProtocolError):
    """Raised for consensus computation errors."""


class VaultError(AegisProtocolError):
    """Raised for vault integrity errors."""


class QuorumError(AegisProtocolError):
    """Raised for multi-party issuance errors."""
