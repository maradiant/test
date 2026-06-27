"""Tests for the consensus aggregation and disagreement detection."""

from __future__ import annotations

from marvin.consensus import DisagreementDetector, RecommendationAggregator
from marvin.domain.enums import CryptoPolicyName, RiskLevel
from marvin.domain.models import SecurityRecommendation


def rec(
    risk: RiskLevel,
    *,
    quarantine: bool = False,
    rotation: bool = True,
    reauth: bool = False,
    confidence: float = 0.8,
    name: str = "a",
    available: bool = True,
) -> SecurityRecommendation:
    return SecurityRecommendation(
        risk_level=risk,
        recommended_policy=CryptoPolicyName.HYBRID_POST_QUANTUM_MODE,
        requires_key_rotation=rotation,
        requires_reauthentication=reauth,
        requires_quarantine=quarantine,
        reasoning_summary="r",
        confidence=confidence,
        advisor_name=name,
        available=available,
    )


def test_aggregator_counts_votes():
    recs = [
        rec(RiskLevel.HIGH, name="o", confidence=0.82),
        rec(RiskLevel.CRITICAL, quarantine=True, name="g", confidence=0.79),
        rec(RiskLevel.HIGH, reauth=True, name="l", confidence=0.76),
        rec(RiskLevel.CRITICAL, quarantine=True, name="c", confidence=0.80),
    ]
    report = RecommendationAggregator().aggregate(recs)
    assert report.available_advisors == 4
    assert report.risk_level_votes == {"HIGH": 2, "CRITICAL": 2}
    assert report.quarantine_votes == 2
    assert report.key_rotation_votes == 4
    assert report.max_risk_level is RiskLevel.CRITICAL
    # Two advisors rate CRITICAL → escalation band is CRITICAL (>=2 votes).
    assert report.escalation_risk_level is RiskLevel.CRITICAL
    assert report.highest_confidence_advisor == "o"


def test_escalation_requires_minimum_votes():
    # Only one CRITICAL → not enough to escalate the band to CRITICAL.
    recs = [
        rec(RiskLevel.MEDIUM, name="a"),
        rec(RiskLevel.MEDIUM, name="b"),
        rec(RiskLevel.CRITICAL, quarantine=True, name="c"),
    ]
    report = RecommendationAggregator(min_escalation_votes=2).aggregate(recs)
    assert report.max_risk_level is RiskLevel.CRITICAL
    assert report.escalation_risk_level is RiskLevel.MEDIUM


def test_aggregator_handles_no_available_advisors():
    recs = [rec(RiskLevel.HIGH, available=False)]
    report = RecommendationAggregator().aggregate(recs)
    assert report.available_advisors == 0
    assert report.escalation_risk_level is RiskLevel.LOW


def test_unanimous_agreement_has_no_disagreement():
    recs = [rec(RiskLevel.HIGH, name=n) for n in ("a", "b", "c")]
    consensus = RecommendationAggregator().aggregate(recs)
    report = DisagreementDetector().detect(recs, consensus)
    assert report.has_disagreement is False
    assert report.quarantine_split is False
    assert report.human_review_required is False


def test_quarantine_split_flags_disagreement():
    recs = [
        rec(RiskLevel.CRITICAL, quarantine=True, name="g"),
        rec(RiskLevel.CRITICAL, quarantine=True, name="c"),
        rec(RiskLevel.HIGH, name="o"),
        rec(RiskLevel.HIGH, name="l"),
    ]
    consensus = RecommendationAggregator().aggregate(recs)
    report = DisagreementDetector().detect(recs, consensus)
    assert report.has_disagreement is True
    assert report.quarantine_split is True
    # Split on quarantine with a CRITICAL present → human review.
    assert report.human_review_required is True


def test_wide_spread_requires_human_review():
    recs = [
        rec(RiskLevel.LOW, name="a"),
        rec(RiskLevel.LOW, name="b"),
        rec(RiskLevel.CRITICAL, quarantine=True, name="c"),
    ]
    consensus = RecommendationAggregator().aggregate(recs)
    report = DisagreementDetector().detect(recs, consensus)
    assert report.risk_level_spread >= 2
    assert report.human_review_required is True
    # The lone escalator should be noted as possibly catching something.
    assert any("higher than its peers" in n for n in report.notes)
