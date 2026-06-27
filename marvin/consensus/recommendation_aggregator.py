"""RecommendationAggregator — turn many advisor opinions into one consensus view.

Counts votes across risk levels, policies, and the boolean action flags, and
derives summary signals the governance/decision layers rely on:

* ``majority_risk_level`` — the most-voted risk band (ties resolve upward).
* ``max_risk_level``      — the single most severe opinion.
* ``escalation_risk_level`` — the most severe band supported by at least
  ``min_escalation_votes`` advisors. This is what MARVIN trusts the council to
  *escalate* to; a lone alarmist cannot move the action on its own.

Only *available* advisors (those that returned a usable recommendation) are
counted.
"""

from __future__ import annotations

from collections import Counter
from typing import Sequence

from ..domain.enums import RiskLevel
from ..domain.models import ConsensusReport, SecurityRecommendation


class RecommendationAggregator:
    def __init__(self, min_escalation_votes: int = 2) -> None:
        self.min_escalation_votes = min_escalation_votes

    def aggregate(
        self, recommendations: Sequence[SecurityRecommendation]
    ) -> ConsensusReport:
        total = len(recommendations)
        available = [r for r in recommendations if r.available]
        n = len(available)

        if n == 0:
            return ConsensusReport(
                total_advisors=total,
                available_advisors=0,
                risk_level_votes={},
                policy_votes={},
                quarantine_votes=0,
                key_rotation_votes=0,
                reauthentication_votes=0,
                majority_risk_level=RiskLevel.LOW,
                max_risk_level=RiskLevel.LOW,
                escalation_risk_level=RiskLevel.LOW,
                highest_confidence_advisor=None,
                mean_confidence=0.0,
                agreement_ratio=0.0,
            )

        risk_votes = Counter(r.risk_level for r in available)
        policy_votes = Counter(r.recommended_policy.value for r in available)
        quarantine_votes = sum(1 for r in available if r.requires_quarantine)
        rotation_votes = sum(1 for r in available if r.requires_key_rotation)
        reauth_votes = sum(1 for r in available if r.requires_reauthentication)

        max_risk = max((r.risk_level for r in available), key=lambda r: r.order)
        majority_risk = self._majority_risk(risk_votes)
        escalation_risk = self._escalation_risk(available)

        top = max(available, key=lambda r: r.confidence)
        mean_conf = round(sum(r.confidence for r in available) / n, 3)
        agreement = round(risk_votes[majority_risk] / n, 3)

        return ConsensusReport(
            total_advisors=total,
            available_advisors=n,
            risk_level_votes={lvl.value: c for lvl, c in risk_votes.items()},
            policy_votes=dict(policy_votes),
            quarantine_votes=quarantine_votes,
            key_rotation_votes=rotation_votes,
            reauthentication_votes=reauth_votes,
            majority_risk_level=majority_risk,
            max_risk_level=max_risk,
            escalation_risk_level=escalation_risk,
            highest_confidence_advisor=top.advisor_name,
            mean_confidence=mean_conf,
            agreement_ratio=agreement,
        )

    @staticmethod
    def _majority_risk(risk_votes: "Counter[RiskLevel]") -> RiskLevel:
        # Most votes wins; ties resolve to the more severe level.
        best = max(risk_votes.items(), key=lambda kv: (kv[1], kv[0].order))
        return best[0]

    def _escalation_risk(
        self, available: Sequence[SecurityRecommendation]
    ) -> RiskLevel:
        # Highest band L such that >= min_escalation_votes advisors rate >= L.
        result = RiskLevel.LOW
        for level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
            supporters = sum(1 for r in available if r.risk_level.order >= level.order)
            if supporters >= self.min_escalation_votes:
                result = level
        return result
