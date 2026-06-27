"""FinalDecisionEngine — the governed authority that issues MARVIN's decision.

Inputs: MARVIN's deterministic baseline score, the council recommendations, the
consensus and disagreement reports, and the guardrail verdict.

Governing principles (in order of authority):

1. **Guardrails are absolute.** Hard rules set the minimum risk band, can
   mandate quarantine, and can forbid inaction. No model can override them.
2. **Deterministic baseline is the floor.** The final risk is never *lower*
   than MARVIN's own transparent score.
3. **The council may escalate, not weaken.** If at least N advisors support a
   more severe band, MARVIN may raise to it — but a single alarmist cannot.
4. **Conservative on disagreement.** Splits trigger the safer action and a
   human-review flag.

The result is a :class:`CouncilDecision`: LLMs advised, MARVIN governed.
"""

from __future__ import annotations

import math
from typing import Optional, Sequence

from ..advisors.base import build_advisor_context
from ..advisors.council import SecurityCouncil
from ..domain.enums import CryptoPolicyName, RiskLevel
from ..domain.models import (
    ConsensusReport,
    CouncilDecision,
    DisagreementReport,
    GuardrailVerdict,
    SecurityRecommendation,
    TelemetrySnapshot,
    ThreatScore,
)
from ..governance.escalation_rules import (
    compute_audit_severity,
    conservative_policy,
)
from ..governance.policy_guardrails import PolicyGuardrails
from ..scoring.threat_scoring_engine import ThreatScoringEngine
from .disagreement_detector import DisagreementDetector
from .recommendation_aggregator import RecommendationAggregator


def _degraded(telemetry: TelemetrySnapshot) -> bool:
    return telemetry.network_latency_ms >= 150.0 or telemetry.packet_loss_percent >= 3.0


class FinalDecisionEngine:
    """Combine baseline, council, and guardrails into one governed decision."""

    def decide(
        self,
        session_id: str,
        telemetry: TelemetrySnapshot,
        baseline: ThreatScore,
        recommendations: Sequence[SecurityRecommendation],
        consensus: ConsensusReport,
        disagreement: DisagreementReport,
        guardrails: GuardrailVerdict,
    ) -> CouncilDecision:
        # 1. Start from the deterministic baseline; raise to the guardrail floor.
        final_risk = RiskLevel.max(baseline.risk_level, guardrails.min_risk_level)

        # 2. The council may escalate (only with >= min_escalation_votes support).
        if (
            consensus.available_advisors > 0
            and consensus.escalation_risk_level.order > final_risk.order
        ):
            final_risk = consensus.escalation_risk_level

        # 3. Quarantine decision (deterministic gate).
        requires_quarantine = self._decide_quarantine(
            final_risk, consensus, guardrails
        )

        # 4. Key rotation & reauthentication (guardrails + risk + council majority).
        n = max(1, consensus.available_advisors)
        majority = math.ceil(n / 2)
        requires_key_rotation = (
            guardrails.require_key_rotation
            or final_risk.order >= RiskLevel.MEDIUM.order
            or consensus.key_rotation_votes >= majority
        )
        requires_reauth = (
            guardrails.require_reauthentication
            or final_risk.order >= RiskLevel.HIGH.order
            or telemetry.failed_auth_attempts >= 5
            or consensus.reauthentication_votes >= majority
        )

        # 5. Map to a concrete policy (quarantine wins; latency-aware otherwise).
        final_policy = conservative_policy(
            final_risk, requires_quarantine, degraded_network=_degraded(telemetry)
        )

        # 6. Never "do nothing" when a guardrail forbids it.
        if guardrails.forbid_no_action and final_policy in {
            CryptoPolicyName.STANDARD_AES_256_GCM,
            CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY,
        }:
            final_policy = CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION
            requires_key_rotation = True
            final_risk = RiskLevel.max(final_risk, RiskLevel.MEDIUM)

        conservative_action = (
            final_risk.order > baseline.risk_level.order
            or requires_quarantine
            or disagreement.has_disagreement
        )
        audit_severity = compute_audit_severity(
            final_risk, requires_quarantine, disagreement.human_review_required
        )
        explanation = self._explain(
            telemetry,
            baseline,
            consensus,
            disagreement,
            guardrails,
            final_risk,
            final_policy,
            requires_quarantine,
        )

        return CouncilDecision(
            session_id=session_id,
            final_risk_level=final_risk,
            final_policy=final_policy,
            requires_key_rotation=requires_key_rotation,
            requires_reauthentication=requires_reauth,
            requires_quarantine=requires_quarantine,
            audit_severity=audit_severity,
            conservative_action=conservative_action,
            human_review_required=disagreement.human_review_required,
            explanation=explanation,
            recommendations=[r.to_dict() for r in recommendations],
            consensus=consensus.to_dict(),
            disagreement=disagreement.to_dict(),
            guardrails=guardrails.to_dict(),
        )

    @staticmethod
    def _decide_quarantine(
        final_risk: RiskLevel,
        consensus: ConsensusReport,
        guardrails: GuardrailVerdict,
    ) -> bool:
        if guardrails.mandatory_quarantine:
            return True
        if not guardrails.quarantine_eligible:
            # Models alone cannot quarantine; a guardrail must make it eligible.
            return False
        n = max(1, consensus.available_advisors)
        # Quarantine is the most disruptive action, so it needs a *strict*
        # majority. A tie (e.g. 2-2) escalates hard instead and flags review.
        strict_majority = (n // 2) + 1
        return (
            final_risk is RiskLevel.CRITICAL
            and consensus.quarantine_votes >= strict_majority
        )

    @staticmethod
    def _explain(
        telemetry: TelemetrySnapshot,
        baseline: ThreatScore,
        consensus: ConsensusReport,
        disagreement: DisagreementReport,
        guardrails: GuardrailVerdict,
        final_risk: RiskLevel,
        final_policy: CryptoPolicyName,
        requires_quarantine: bool,
    ) -> str:
        q = consensus.quarantine_votes
        n = consensus.available_advisors
        escalators = sum(
            1
            for lvl, c in consensus.risk_level_votes.items()
            if RiskLevel(lvl).order >= RiskLevel.HIGH.order
            for _ in range(c)
        )
        parts = [
            f"{n} independent reasoning engines evaluated this event.",
            f"{q} recommended quarantine; {escalators} rated risk HIGH or above.",
        ]
        if guardrails.triggered_rules:
            parts.append(
                "Deterministic guardrails fired: "
                + ", ".join(guardrails.triggered_rules)
                + "."
            )
        parts.append(
            f"MARVIN baseline was {baseline.risk_level.value}; governed final "
            f"risk is {final_risk.value}."
        )
        if requires_quarantine:
            parts.append(
                "Because sensitive data and active compromise indicators were "
                "present, MARVIN selected the conservative posture: "
                f"{final_policy.value}."
            )
        else:
            parts.append(f"MARVIN selected {final_policy.value}.")
        if disagreement.human_review_required:
            parts.append("Disagreement was material — flagged for human review.")
        return " ".join(parts)


# --------------------------------------------------------------------------- #
# Convenience pipeline: telemetry → council → consensus → governance → decision
# --------------------------------------------------------------------------- #


class CouncilDeliberation:
    """Bundle of every artefact produced while deliberating on one event."""

    __slots__ = (
        "recommendations",
        "consensus",
        "disagreement",
        "guardrails",
        "decision",
    )

    def __init__(self, recommendations, consensus, disagreement, guardrails, decision):
        self.recommendations = recommendations
        self.consensus = consensus
        self.disagreement = disagreement
        self.guardrails = guardrails
        self.decision = decision

    def to_dict(self) -> dict:
        return {
            "recommendations": [r.to_dict() for r in self.recommendations],
            "consensus": self.consensus.to_dict(),
            "disagreement": self.disagreement.to_dict(),
            "guardrails": self.guardrails.to_dict(),
            "decision": self.decision.to_dict(),
        }


def deliberate(
    telemetry: TelemetrySnapshot,
    council: SecurityCouncil,
    *,
    baseline_engine: Optional[ThreatScoringEngine] = None,
    aggregator: Optional[RecommendationAggregator] = None,
    detector: Optional[DisagreementDetector] = None,
    guardrails: Optional[PolicyGuardrails] = None,
    final_engine: Optional[FinalDecisionEngine] = None,
    baseline: Optional[ThreatScore] = None,
) -> CouncilDeliberation:
    """Run the full council pipeline for a single telemetry event."""
    baseline_engine = baseline_engine or ThreatScoringEngine()
    aggregator = aggregator or RecommendationAggregator()
    detector = detector or DisagreementDetector()
    guardrails = guardrails or PolicyGuardrails()
    final_engine = final_engine or FinalDecisionEngine()

    baseline = baseline or baseline_engine.score(telemetry)
    context = build_advisor_context(telemetry, baseline)

    recommendations = council.convene(context)
    consensus = aggregator.aggregate(recommendations)
    disagreement = detector.detect(recommendations, consensus)
    verdict = guardrails.evaluate(telemetry)
    decision = final_engine.decide(
        session_id=telemetry.session_id,
        telemetry=telemetry,
        baseline=baseline,
        recommendations=recommendations,
        consensus=consensus,
        disagreement=disagreement,
        guardrails=verdict,
    )
    return CouncilDeliberation(
        recommendations=recommendations,
        consensus=consensus,
        disagreement=disagreement,
        guardrails=verdict,
        decision=decision,
    )
