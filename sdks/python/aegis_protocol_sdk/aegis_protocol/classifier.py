"""
aegis_protocol.classifier
-----------------
SemanticClassifier — scoring with pluggable backends.
"""

import dataclasses
from typing import Callable, Optional

from aegis_protocol.crypto_utils import sha256_hex


@dataclasses.dataclass
class SemanticScore:
    payload_hash:            str = ""
    authority:               float = 0.0
    sensitivity:             float = 0.0
    authority_confidence:    float = 0.0
    sensitivity_confidence:  float = 0.0
    backend:                 str = "unknown"
    scored_at:               int = 0


# Type alias for a scoring backend callable
ScoringBackend = Callable[[str, int], SemanticScore]


def make_stub_backend(authority: float, sensitivity: float,
                      confidence: float = 0.92) -> ScoringBackend:
    """
    Factory that returns a simple stub backend with fixed scores.
    Useful for unit testing.
    """
    def _backend(payload: str, now: int) -> SemanticScore:
        return SemanticScore(
            payload_hash=sha256_hex(payload),
            authority=authority,
            sensitivity=sensitivity,
            authority_confidence=confidence,
            sensitivity_confidence=confidence,
            backend="stub",
            scored_at=now,
        )
    return _backend


class SemanticClassifier:
    """
    Scores payloads for authority and sensitivity.

    Parameters
    ----------
    backend:
        A callable ``(payload: str, now: int) -> SemanticScore``.
    """

    def __init__(self, backend: ScoringBackend):
        self._backend = backend

    def score(self, payload: str, now: int) -> SemanticScore:
        result = self._backend(payload, now)
        # Validate ranges
        if not (-1.0 <= result.authority <= 1.0):
            raise ValueError(f"authority out of range: {result.authority}")
        if not (0.0 <= result.sensitivity <= 1.0):
            raise ValueError(f"sensitivity out of range: {result.sensitivity}")
        return result
