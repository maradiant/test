"""DisagreementDetector — surface where the advisors diverge.

Disagreement is not failure; it is signal. The detector answers:

* Did the advisors agree on the risk band?
* Did they split on quarantine?
* Did one model catch something the others missed (a lone escalator)?
* Is the divergence wide enough that a human should review?

When the council is split on a serious action, MARVIN takes the conservative
path *and* flags the decision for human review.
"""

from __future__ import annotations

from typing import Sequence

from ..domain.models import (
    ConsensusReport,
    DisagreementReport,
    SecurityRecommendation,
)


class DisagreementDetector:
    def detect(
        self,
        recommendations: Sequence[SecurityRecommendation],
        consensus: ConsensusReport,
    ) -> DisagreementReport:
        available = [r for r in recommendations if r.available]
        notes: list[str] = []

        if len(available) <= 1:
            return DisagreementReport(
                has_disagreement=False,
                risk_level_spread=0,
                quarantine_split=False,
                outliers=[],
                human_review_required=False,
                notes=["Insufficient advisors for disagreement analysis."]
                if not available
                else [],
            )

        orders = [r.risk_level.order for r in available]
        spread = max(orders) - min(orders)

        quarantine_flags = [r.requires_quarantine for r in available]
        quarantine_split = any(quarantine_flags) and not all(quarantine_flags)

        majority = consensus.majority_risk_level
        outliers = [
            r.advisor_name
            for r in available
            if abs(r.risk_level.order - majority.order) >= 1
        ]

        # A lone, more-severe advisor may have caught something others missed.
        max_order = max(orders)
        top_count = sum(1 for o in orders if o == max_order)
        if top_count == 1 and spread >= 1:
            catcher = next(
                r.advisor_name for r in available if r.risk_level.order == max_order
            )
            notes.append(
                f"'{catcher}' rated risk higher than its peers — possible early "
                "signal others missed."
            )

        if quarantine_split:
            yes = [r.advisor_name for r in available if r.requires_quarantine]
            notes.append(
                f"Split on quarantine: {len(yes)}/{len(available)} advised "
                f"quarantine ({', '.join(yes)})."
            )

        if spread >= 1:
            notes.append(
                f"Risk-level spread of {spread} band(s) across the council."
            )

        has_disagreement = spread >= 1 or quarantine_split

        # Human review when the divergence is wide or splits on a severe action.
        human_review = spread >= 2 or (
            quarantine_split and consensus.max_risk_level.value == "CRITICAL"
        )
        if human_review:
            notes.append("Flagged for human review due to material disagreement.")

        return DisagreementReport(
            has_disagreement=has_disagreement,
            risk_level_spread=spread,
            quarantine_split=quarantine_split,
            outliers=sorted(set(outliers)),
            human_review_required=human_review,
            notes=notes,
        )
