"""
aegis.consensus
~~~~~~~~~~~~~~~
BFT Scalar Consensus via the geometric median (Weiszfeld's algorithm).

When multiple agents independently score the same payload, the coordinator
applies the geometric median to their (authority, sensitivity) pairs rather
than the arithmetic mean. This is resistant to a single compromised agent
inflating or deflating scores to evade or trigger policy rules.

Fault tolerance bound: f <= floor((n-1)/3) Byzantine agents out of n total.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional

from .classifier import SemanticScore
from .exceptions import ConsensusInsufficientAgentsError, ConsensusError


@dataclass
class AgentScore:
    """A SemanticScore attributed to a specific agent."""
    agent_id: str
    score: SemanticScore


@dataclass
class ConsensusResult:
    """Result of BFT geometric median consensus over a set of AgentScores.

    Attributes:
        authority:           Geometric median authority score.
        sensitivity:         Geometric median sensitivity score.
        num_agents:          Number of agents that submitted scores.
        fault_tolerance:     Maximum Byzantine agents tolerated: floor((n-1)/3).
        outlier_detected:    True if any agent deviated beyond the threshold.
        outlier_agent_ids:   IDs of agents flagged as outliers.
    """
    authority: float
    sensitivity: float
    num_agents: int
    fault_tolerance: int
    outlier_detected: bool
    outlier_agent_ids: List[str] = field(default_factory=list)

    def to_semantic_score(
        self,
        payload_hash: str,
        scored_at: int,
        confidence: float = 0.9,
        classifier_version: str = "bft-consensus-0.1",
    ) -> SemanticScore:
        """Convert the consensus result into a SemanticScore for PolicyEngine input.

        Args:
            payload_hash:       Hash of the payload being evaluated.
            scored_at:          Timestamp.
            confidence:         Confidence to assign (default 0.9).
            classifier_version: Version string for the consensus scorer.

        Returns:
            A :class:`~aegis.classifier.SemanticScore`.
        """
        return SemanticScore(
            payload_hash=payload_hash,
            authority=self.authority,
            sensitivity=self.sensitivity,
            authority_confidence=confidence,
            sensitivity_confidence=confidence,
            classifier_version=classifier_version,
            scored_at=scored_at,
        )

    def __repr__(self) -> str:
        return (
            f"ConsensusResult(auth={self.authority:.3f}, "
            f"sens={self.sensitivity:.3f}, "
            f"n={self.num_agents}, "
            f"ft={self.fault_tolerance}, "
            f"outliers={self.outlier_agent_ids})"
        )


def _geometric_median_2d(
    points: List[tuple],
    iterations: int = 100,
    epsilon: float = 1e-6,
) -> tuple:
    """Compute the geometric median of 2D points via Weiszfeld's algorithm.

    The geometric median minimises sum of Euclidean distances to all points.
    In 1D this reduces to the standard median. In 2D it is computed iteratively.

    Args:
        points:     List of (x, y) float tuples.
        iterations: Maximum Weiszfeld iterations. Default 100.
        epsilon:    Convergence threshold. Default 1e-6.

    Returns:
        (median_x, median_y) float tuple.

    Raises:
        ValueError: If points is empty.
    """
    if not points:
        raise ValueError("_geometric_median_2d: points must not be empty")
    if len(points) == 1:
        return points[0]

    # Initial estimate: arithmetic centroid
    n = len(points)
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n

    for _ in range(iterations):
        num_x = num_y = denom = 0.0
        for px, py in points:
            dist = math.sqrt((px - mx) ** 2 + (py - my) ** 2)
            if dist < epsilon:
                continue  # skip coincident points
            w = 1.0 / dist
            num_x += px * w
            num_y += py * w
            denom += w

        if denom < epsilon:
            break

        new_mx, new_my = num_x / denom, num_y / denom

        if abs(new_mx - mx) < epsilon and abs(new_my - my) < epsilon:
            break

        mx, my = new_mx, new_my

    return (mx, my)


class BFTConsensusEngine:
    """Aggregates SemanticScores from multiple agents using BFT geometric median.

    Tolerates at most ``floor((n-1)/3)`` Byzantine agents out of ``n`` total.
    Flags outlier agents whose scores deviate from the consensus beyond
    ``outlier_threshold`` Euclidean distance in (authority, sensitivity) space.

    Args:
        outlier_threshold: Euclidean distance in (auth, sens) space beyond
                           which an agent is flagged. Default 0.3.
        min_agents:        Minimum agents required to compute consensus.
                           Default 1 (no minimum enforced beyond non-empty).

    Example::

        engine = BFTConsensusEngine(outlier_threshold=0.3)

        scores = [
            AgentScore("agent-a", classifier_a.score(payload)),
            AgentScore("agent-b", classifier_b.score(payload)),
            AgentScore("agent-c", classifier_c.score(payload)),  # may be rogue
        ]

        result = engine.compute(scores)

        if result.outlier_detected:
            for agent_id in result.outlier_agent_ids:
                print(f"[WARN] Outlier detected: {agent_id}")

        policy_score = result.to_semantic_score(payload_hash, now)
        decision = policy_engine.evaluate(policy_score)
    """

    def __init__(
        self,
        outlier_threshold: float = 0.3,
        min_agents: int = 1,
    ) -> None:
        if outlier_threshold <= 0:
            raise ValueError("outlier_threshold must be positive")
        self._threshold = outlier_threshold
        self._min_agents = min_agents

    def compute(self, agent_scores: List[AgentScore]) -> ConsensusResult:
        """Compute the BFT geometric median consensus.

        Args:
            agent_scores: List of :class:`AgentScore` from all participating agents.

        Returns:
            A :class:`ConsensusResult`.

        Raises:
            ConsensusInsufficientAgentsError: Fewer agents than ``min_agents``.
        """
        if len(agent_scores) < self._min_agents:
            raise ConsensusInsufficientAgentsError(
                len(agent_scores), self._min_agents
            )
        if not agent_scores:
            raise ConsensusInsufficientAgentsError(0, 1)

        n = len(agent_scores)
        points = [
            (a.score.authority, a.score.sensitivity)
            for a in agent_scores
        ]

        med_auth, med_sens = _geometric_median_2d(points)

        outlier_ids = []
        for agent in agent_scores:
            da = agent.score.authority - med_auth
            ds = agent.score.sensitivity - med_sens
            if math.sqrt(da * da + ds * ds) > self._threshold:
                outlier_ids.append(agent.agent_id)

        return ConsensusResult(
            authority=float(med_auth),
            sensitivity=float(med_sens),
            num_agents=n,
            fault_tolerance=(n - 1) // 3,
            outlier_detected=bool(outlier_ids),
            outlier_agent_ids=outlier_ids,
        )

    def __repr__(self) -> str:
        return (
            f"BFTConsensusEngine(outlier_threshold={self._threshold}, "
            f"min_agents={self._min_agents})"
        )
