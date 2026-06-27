"""Consensus layer: aggregate advisor recommendations and detect disagreement."""

from .disagreement_detector import DisagreementDetector
from .final_decision_engine import (
    CouncilDeliberation,
    FinalDecisionEngine,
    deliberate,
)
from .recommendation_aggregator import RecommendationAggregator

__all__ = [
    "RecommendationAggregator",
    "DisagreementDetector",
    "FinalDecisionEngine",
    "CouncilDeliberation",
    "deliberate",
]
