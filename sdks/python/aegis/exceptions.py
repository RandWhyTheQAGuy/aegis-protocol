"""
aegis.exceptions
~~~~~~~~~~~~~~~~
Typed exceptions for every failure mode in the Aegis Protocol SDK.
Catching specific exception types is preferred over catching AegisError.
"""


class AegisError(Exception):
    """Base class for all Aegis Protocol exceptions."""


# ---------------------------------------------------------------------------
# Passport exceptions
# ---------------------------------------------------------------------------

class PassportError(AegisError):
    """Base class for passport-related errors."""


class PassportExpiredError(PassportError):
    """Raised when a passport's expires_at timestamp is in the past."""

    def __init__(self, model_id: str, expired_at: int, now: int) -> None:
        self.model_id = model_id
        self.expired_at = expired_at
        self.now = now
        super().__init__(
            f"Passport for '{model_id}' expired at {expired_at} (now={now})"
        )


class PassportSignatureError(PassportError):
    """Raised when HMAC verification of a passport fails."""

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id
        super().__init__(
            f"Passport signature verification failed for '{model_id}'"
        )


class PassportRegistryMismatchError(PassportError):
    """Raised when a passport's registry_version does not match the local registry."""

    def __init__(self, passport_version: str, local_version: str) -> None:
        self.passport_version = passport_version
        self.local_version = local_version
        super().__init__(
            f"Passport registry version '{passport_version}' does not match "
            f"local registry version '{local_version}'"
        )


class PassportSchemaError(PassportError):
    """Raised when a passport payload fails JSON Schema validation."""


# ---------------------------------------------------------------------------
# Handshake exceptions
# ---------------------------------------------------------------------------

class HandshakeError(AegisError):
    """Base class for handshake-related errors."""


class HandshakeRejectError(HandshakeError):
    """Raised when a HELLO_REJECT is received during handshake."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"Handshake rejected: {reason}" + (f" ({detail})" if detail else ""))


class HandshakeSchemaMismatchError(HandshakeError):
    """Raised when proposed and accepted schema versions are incompatible."""

    def __init__(self, proposed: str, accepted: str) -> None:
        self.proposed = proposed
        self.accepted = accepted
        super().__init__(
            f"Schema mismatch: proposed '{proposed}', peer accepts '{accepted}'"
        )


class HandshakeTimeoutError(HandshakeError):
    """Raised when a handshake step does not complete within the timeout window."""


# ---------------------------------------------------------------------------
# Classifier exceptions
# ---------------------------------------------------------------------------

class ClassifierError(AegisError):
    """Base class for classifier-related errors."""


class ClassifierBackendError(ClassifierError):
    """Raised when the classifier backend returns an error or is unreachable."""

    def __init__(self, message: str, backend_version: str = "") -> None:
        self.backend_version = backend_version
        super().__init__(f"Classifier backend error: {message}")


class ClassifierScoreRangeError(ClassifierError):
    """Raised when a classifier returns a score outside its valid range."""

    def __init__(self, field: str, value: float, valid_range: str) -> None:
        self.field = field
        self.value = value
        self.valid_range = valid_range
        super().__init__(
            f"Classifier returned out-of-range value for '{field}': "
            f"{value} (valid range: {valid_range})"
        )


# ---------------------------------------------------------------------------
# Policy exceptions
# ---------------------------------------------------------------------------

class PolicyError(AegisError):
    """Base class for policy-related errors."""


class PolicyDenyError(PolicyError):
    """Raised when a payload is denied by the Policy Engine. Not always raised —
    callers may prefer to check PolicyDecision.action instead."""

    def __init__(self, rule_id: str, payload_hash: str) -> None:
        self.rule_id = rule_id
        self.payload_hash = payload_hash
        super().__init__(
            f"Payload '{payload_hash[:16]}...' denied by rule '{rule_id}'"
        )


class PolicyRuleValidationError(PolicyError):
    """Raised when a policy rule set fails schema validation on load."""


# ---------------------------------------------------------------------------
# Session exceptions
# ---------------------------------------------------------------------------

class SessionError(AegisError):
    """Base class for session-related errors."""


class SessionStateError(SessionError):
    """Raised when an operation is called in an invalid session state."""

    def __init__(self, operation: str, current_state: str) -> None:
        self.operation = operation
        self.current_state = current_state
        super().__init__(
            f"Cannot call '{operation}' in session state '{current_state}'"
        )


class SessionTaintError(SessionError):
    """Raised when a session has been quarantined and tainted payloads were detected."""

    def __init__(self, session_id: str, incident_id: str) -> None:
        self.session_id = session_id
        self.incident_id = incident_id
        super().__init__(
            f"Session '{session_id[:16]}...' quarantined. Incident: {incident_id[:16]}..."
        )


class SessionQuarantineError(SessionError):
    """Raised when a payload is rejected because the session is in QUARANTINE state."""


# ---------------------------------------------------------------------------
# Vault exceptions
# ---------------------------------------------------------------------------

class VaultError(AegisError):
    """Base class for vault-related errors."""


class VaultChainIntegrityError(VaultError):
    """Raised when vault chain verification fails, indicating tampering."""

    def __init__(self, sequence: int, detail: str) -> None:
        self.sequence = sequence
        self.detail = detail
        super().__init__(
            f"Vault chain integrity failure at sequence {sequence}: {detail}"
        )


class VaultEntrySchemaError(VaultError):
    """Raised when a vault entry fails JSON Schema validation."""


# ---------------------------------------------------------------------------
# Registry exceptions
# ---------------------------------------------------------------------------

class RegistryError(AegisError):
    """Base class for registry-related errors."""


class RegistryIntegrityError(RegistryError):
    """Raised when the registry file's registry_hash does not match its contents."""


class RegistryVersionError(RegistryError):
    """Raised when an incompatible registry version is loaded."""


# ---------------------------------------------------------------------------
# Consensus exceptions
# ---------------------------------------------------------------------------

class ConsensusError(AegisError):
    """Base class for BFT consensus errors."""


class ConsensusInsufficientAgentsError(ConsensusError):
    """Raised when fewer than the minimum required agents submit scores."""

    def __init__(self, provided: int, minimum: int) -> None:
        self.provided = provided
        self.minimum = minimum
        super().__init__(
            f"Insufficient agents for consensus: {provided} provided, "
            f"{minimum} required"
        )
