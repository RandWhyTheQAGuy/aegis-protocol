"""
aegis_protocol.consensus
----------------
BFTConsensusEngine — geometric median, outlier detection, fault tolerance.
"""

import dataclasses
import math
from typing import List

from aegis_protocol.classifier import SemanticScore


@dataclasses.dataclass
class AgentScore:
    agent_id: str
    score:    SemanticScore


@dataclasses.dataclass
class ConsensusResult:
    authority:         float
    sensitivity:       float
    outlier_detected:  bool
    outlier_agent_ids: List[str]
    fault_tolerance:   int  # f = floor((n-1)/3)


def _geometric_median_1d(values: List[float], iterations: int = 100) -> float:
    """
    Weiszfeld algorithm for the geometric median of scalar values.
    Falls back to arithmetic mean for degenerate cases.
    """
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]

    # Initial estimate: arithmetic mean
    estimate = sum(values) / len(values)
    for _ in range(iterations):
        weights = []
        for v in values:
            dist = abs(v - estimate)
            weights.append(1.0 / max(dist, 1e-10))
        total_w = sum(weights)
        estimate = sum(w * v for w, v in zip(weights, values)) / total_w
    return estimate


class BFTConsensusEngine:
    """
    Computes a Byzantine-fault-tolerant consensus score from a set of
    per-agent SemanticScores.

    Parameters
    ----------
    outlier_threshold:
        Maximum Euclidean distance from the geometric median before an
        agent is considered an outlier.
    """

    def __init__(self, outlier_threshold: float = 0.3):
        self._threshold = outlier_threshold

    def compute(self, agent_scores: List[AgentScore]) -> ConsensusResult:
        n = len(agent_scores)
        fault_tolerance = (n - 1) // 3

        authorities   = [a.score.authority   for a in agent_scores]
        sensitivities = [a.score.sensitivity for a in agent_scores]

        median_auth = _geometric_median_1d(authorities)
        median_sens = _geometric_median_1d(sensitivities)

        outliers: List[str] = []
        for a in agent_scores:
            dist = math.sqrt(
                (a.score.authority   - median_auth) ** 2 +
                (a.score.sensitivity - median_sens) ** 2
            )
            if dist > self._threshold:
                outliers.append(a.agent_id)

        # Recompute median excluding outliers for the final consensus value
        clean = [a for a in agent_scores if a.agent_id not in outliers]
        if clean:
            final_auth = sum(a.score.authority   for a in clean) / len(clean)
            final_sens = sum(a.score.sensitivity for a in clean) / len(clean)
        else:
            final_auth = median_auth
            final_sens = median_sens

        return ConsensusResult(
            authority=final_auth,
            sensitivity=final_sens,
            outlier_detected=bool(outliers),
            outlier_agent_ids=outliers,
            fault_tolerance=fault_tolerance,
        )
