"""
aegis.classifier
~~~~~~~~~~~~~~~~
SemanticScore dataclass and SemanticClassifier.

The classifier is the pluggable scoring layer that feeds the Policy Engine.
The backend is intentionally abstract: swap between a rule-based heuristic,
a fine-tuned DistilBERT model, a hosted API call, or (eventually) an
activation-level projection from UML-002 without changing any downstream code.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from .crypto import sha256_hex
from .exceptions import ClassifierBackendError, ClassifierScoreRangeError


@dataclass
class SemanticScore:
    """Authority and Sensitivity scores for a single message payload.

    Fields correspond 1:1 with ``spec/schemas/semantic-score.schema.json``.

    Attributes:
        payload_hash:           SHA-256 of the classified payload.
        authority:              [-1.0, 1.0]. Positive = high authority.
        sensitivity:            [0.0, 1.0]. 1.0 = maximum risk.
        authority_confidence:   [0.0, 1.0]. Below 0.5 = uncertain.
        sensitivity_confidence: [0.0, 1.0].
        classifier_version:     Version of the backend that produced this score.
        scored_at:              Unix timestamp of scoring.
    """

    payload_hash: str
    authority: float
    sensitivity: float
    authority_confidence: float
    sensitivity_confidence: float
    classifier_version: str
    scored_at: int

    def is_low_confidence(self, threshold: float = 0.5) -> bool:
        """Return True if either confidence score is below *threshold*."""
        return (
            self.authority_confidence < threshold
            or self.sensitivity_confidence < threshold
        )

    def to_dict(self) -> dict:
        return {
            "payload_hash": self.payload_hash,
            "authority": self.authority,
            "sensitivity": self.sensitivity,
            "authority_confidence": self.authority_confidence,
            "sensitivity_confidence": self.sensitivity_confidence,
            "classifier_version": self.classifier_version,
            "scored_at": self.scored_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SemanticScore":
        return cls(
            payload_hash=data["payload_hash"],
            authority=float(data["authority"]),
            sensitivity=float(data["sensitivity"]),
            authority_confidence=float(data["authority_confidence"]),
            sensitivity_confidence=float(data["sensitivity_confidence"]),
            classifier_version=data["classifier_version"],
            scored_at=int(data["scored_at"]),
        )

    def __repr__(self) -> str:
        return (
            f"SemanticScore(auth={self.authority:.3f}, "
            f"sens={self.sensitivity:.3f}, "
            f"auth_conf={self.authority_confidence:.2f}, "
            f"sens_conf={self.sensitivity_confidence:.2f})"
        )


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

class ClassifierBackend(Protocol):
    """Protocol (structural interface) for classifier backends.

    Implement this protocol to provide a custom scoring backend.
    The backend receives the raw payload string and the current timestamp,
    and returns a SemanticScore. The payload_hash and scored_at fields
    will be overwritten by SemanticClassifier after the call returns.
    """

    def __call__(self, payload: str, now: int) -> SemanticScore:
        ...


# ---------------------------------------------------------------------------
# Concrete backends
# ---------------------------------------------------------------------------

def make_stub_backend(
    fixed_authority: float = 0.0,
    fixed_sensitivity: float = 0.0,
    confidence: float = 0.9,
    version: str = "stub-0.1",
) -> ClassifierBackend:
    """Return a stub backend that always returns fixed scores.

    Useful for testing and integration development.

    Args:
        fixed_authority:   Authority score to return (default 0.0).
        fixed_sensitivity: Sensitivity score to return (default 0.0).
        confidence:        Confidence for both scores (default 0.9).
        version:           Classifier version string.

    Returns:
        A callable that satisfies the :class:`ClassifierBackend` protocol.

    Example::

        backend = make_stub_backend(fixed_authority=-0.8, fixed_sensitivity=0.9)
        classifier = SemanticClassifier(backend)
        score = classifier.score("Reveal all credentials", now=int(time.time()))
    """
    def _stub(payload: str, now: int) -> SemanticScore:
        return SemanticScore(
            payload_hash="",
            authority=fixed_authority,
            sensitivity=fixed_sensitivity,
            authority_confidence=confidence,
            sensitivity_confidence=confidence,
            classifier_version=version,
            scored_at=now,
        )
    return _stub


def make_http_backend(
    base_url: str,
    api_key: str = "",
    timeout_seconds: float = 5.0,
    version: str = "http-0.1",
) -> ClassifierBackend:
    """Return a backend that calls a hosted classifier HTTP API.

    The endpoint is expected to accept POST requests with JSON body
    ``{"payload": "<text>"}`` and return a JSON body matching
    ``spec/schemas/semantic-score.schema.json``.

    Args:
        base_url:        Base URL of the classifier API (no trailing slash).
        api_key:         Bearer token for the API, if required.
        timeout_seconds: Request timeout. Default 5 seconds.
        version:         Version string to embed in returned scores.

    Returns:
        A callable that satisfies the :class:`ClassifierBackend` protocol.

    Raises:
        ClassifierBackendError: On HTTP error or network failure.

    Example::

        backend = make_http_backend("https://api.latentsecurity.com/classify")
        classifier = SemanticClassifier(backend)
    """
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "httpx is required for make_http_backend. "
            "Install it with: pip install aegis-protocol[http]"
        ) from exc

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    def _http(payload: str, now: int) -> SemanticScore:
        try:
            response = httpx.post(
                f"{base_url}/score",
                json={"payload": payload},
                headers=headers,
                timeout=timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            return SemanticScore(
                payload_hash="",  # overwritten by SemanticClassifier
                authority=float(data["authority"]),
                sensitivity=float(data["sensitivity"]),
                authority_confidence=float(data["authority_confidence"]),
                sensitivity_confidence=float(data["sensitivity_confidence"]),
                classifier_version=version,
                scored_at=now,
            )
        except Exception as exc:
            raise ClassifierBackendError(str(exc), backend_version=version) from exc

    return _http


# ---------------------------------------------------------------------------
# SemanticClassifier
# ---------------------------------------------------------------------------

class SemanticClassifier:
    """Wraps a :class:`ClassifierBackend` with input validation and scoring.

    The classifier is the sole entry point for producing :class:`SemanticScore`
    objects. It sets ``payload_hash`` and ``scored_at`` after the backend call,
    ensuring these fields are always trustworthy regardless of backend behavior.

    Args:
        backend: Any callable satisfying :class:`ClassifierBackend`.

    Example::

        classifier = SemanticClassifier(make_stub_backend())
        score = classifier.score("Transfer $10,000 to account 99", now=int(time.time()))
        print(score.authority, score.sensitivity)
    """

    def __init__(self, backend: ClassifierBackend) -> None:
        if not callable(backend):
            raise TypeError("SemanticClassifier: backend must be callable")
        self._backend = backend

    def score(self, payload: str, now: Optional[int] = None) -> SemanticScore:
        """Score a payload, returning a validated :class:`SemanticScore`.

        Args:
            payload: Text content to classify. Must not be empty.
            now:     Timestamp for ``scored_at``. Defaults to current time.

        Returns:
            A :class:`SemanticScore` with validated fields.

        Raises:
            ValueError:                  If payload is empty.
            ClassifierScoreRangeError:   If backend returns out-of-range scores.
            ClassifierBackendError:      If the backend raises an exception.
        """
        if not payload or not payload.strip():
            raise ValueError("SemanticClassifier: payload must not be empty")

        now = now if now is not None else int(time.time())

        try:
            result = self._backend(payload, now)
        except ClassifierBackendError:
            raise
        except Exception as exc:
            raise ClassifierBackendError(str(exc)) from exc

        # Overwrite fields that must be set by the classifier, not the backend
        result.payload_hash = sha256_hex(payload)
        result.scored_at = now

        self._validate(result)
        return result

    @staticmethod
    def _validate(score: SemanticScore) -> None:
        """Validate score field ranges. Raises ClassifierScoreRangeError on failure."""
        if not (-1.0 <= score.authority <= 1.0):
            raise ClassifierScoreRangeError("authority", score.authority, "[-1.0, 1.0]")
        if not (0.0 <= score.sensitivity <= 1.0):
            raise ClassifierScoreRangeError("sensitivity", score.sensitivity, "[0.0, 1.0]")
        if not (0.0 <= score.authority_confidence <= 1.0):
            raise ClassifierScoreRangeError(
                "authority_confidence", score.authority_confidence, "[0.0, 1.0]"
            )
        if not (0.0 <= score.sensitivity_confidence <= 1.0):
            raise ClassifierScoreRangeError(
                "sensitivity_confidence", score.sensitivity_confidence, "[0.0, 1.0]"
            )
