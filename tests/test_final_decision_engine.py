"""Tests for the governed final decision engine — LLMs advise, MARVIN governs."""

from __future__ import annotations

from marvin.advisors import SecurityCouncil, build_advisor_context
from marvin.advisors.base import StaticAdvisor
from marvin.consensus import (
    DisagreementDetector,
    FinalDecisionEngine,
    RecommendationAggregator,
    deliberate,
)
from marvin.domain.enums import CryptoPolicyName, DataSensitivity, RiskLevel
from marvin.domain.models import SecurityRecommendation
from marvin.governance import PolicyGuardrails
from marvin.scoring.threat_scoring_engine import ThreatScoringEngine


def _rec(risk, *, quarantine=False, name="m"):
    return SecurityRecommendation(
        risk_level=risk,
        recommended_policy=CryptoPolicyName.STANDARD_AES_256_GCM,
        requires_key_rotation=False,
        requires_reauthentication=False,
        requires_quarantine=quarantine,
        reasoning_summary="r",
        confidence=0.8,
        advisor_name=name,
    )


def _decide(make_telemetry, recommendations, **telemetry_overrides):
    telemetry = make_telemetry(**telemetry_overrides)
    baseline = ThreatScoringEngine().score(telemetry)
    consensus = RecommendationAggregator().aggregate(recommendations)
    disagreement = DisagreementDetector().detect(recommendations, consensus)
    guardrails = PolicyGuardrails().evaluate(telemetry)
    return FinalDecisionEngine().decide(
        session_id=telemetry.session_id,
        telemetry=telemetry,
        baseline=baseline,
        recommendations=recommendations,
        consensus=consensus,
        disagreement=disagreement,
        guardrails=guardrails,
    )


def test_canonical_interception_yields_escalation_or_quarantine(make_telemetry):
    """The headline scenario from the spec."""
    decision = deliberate(
        make_telemetry(
            anomaly_score=0.40,
            endpoint_trust_score=0.42,
            failed_auth_attempts=9,
            geo_velocity_risk=0.87,
            data_sensitivity=DataSensitivity.RESTRICTED,
            suspected_interception=True,
            adversary_pressure=0.50,
            network_latency_ms=90.0,
            packet_loss_percent=4.0,
        ),
        SecurityCouncil.default(),
    ).decision
    assert decision.final_policy in {
        CryptoPolicyName.QUANTUM_ESCALATED_MODE,
        CryptoPolicyName.SESSION_QUARANTINE,
    }
    assert decision.final_risk_level is RiskLevel.CRITICAL
    assert decision.human_review_required is True
    assert "INTERCEPTION_ON_SENSITIVE_DATA" in decision.guardrails["triggered_rules"]


def test_models_cannot_lower_below_deterministic_baseline(make_telemetry):
    # Strong telemetry (baseline HIGH+), but every model wrongly says LOW.
    recs = [_rec(RiskLevel.LOW, name=n) for n in ("a", "b", "c", "d")]
    decision = _decide(
        make_telemetry,
        recs,
        anomaly_score=0.6,
        endpoint_trust_score=0.3,
        adversary_pressure=0.7,
        suspected_interception=True,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    # Governance floors risk well above the (wrong) unanimous LOW vote.
    assert decision.final_risk_level.order >= RiskLevel.HIGH.order
    assert decision.final_policy is not CryptoPolicyName.STANDARD_AES_256_GCM


def test_guardrail_forbids_doing_nothing(make_telemetry):
    # Interception on restricted data: even if models say LOW/do-nothing, the
    # guardrail forbids inaction and forces at least frequent rotation.
    recs = [_rec(RiskLevel.LOW, name=n) for n in ("a", "b", "c", "d")]
    decision = _decide(
        make_telemetry,
        recs,
        suspected_interception=True,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    assert decision.final_policy is not CryptoPolicyName.STANDARD_AES_256_GCM
    assert decision.requires_key_rotation is True


def test_single_model_cannot_escalate_action_alone(make_telemetry):
    # Calm telemetry, three models LOW, one lone CRITICAL → action stays calm
    # but the disagreement is flagged for human review.
    recs = [
        _rec(RiskLevel.LOW, name="a"),
        _rec(RiskLevel.LOW, name="b"),
        _rec(RiskLevel.LOW, name="c"),
        _rec(RiskLevel.CRITICAL, quarantine=True, name="d"),
    ]
    decision = _decide(make_telemetry, recs)
    assert decision.final_risk_level is RiskLevel.LOW
    assert decision.requires_quarantine is False
    assert decision.human_review_required is True


def test_council_majority_escalates_risk(make_telemetry):
    # Calm telemetry but 3 of 4 models say HIGH → council escalates to HIGH.
    recs = [
        _rec(RiskLevel.HIGH, name="a"),
        _rec(RiskLevel.HIGH, name="b"),
        _rec(RiskLevel.HIGH, name="c"),
        _rec(RiskLevel.LOW, name="d"),
    ]
    decision = _decide(make_telemetry, recs)
    assert decision.final_risk_level is RiskLevel.HIGH


def test_mandatory_guardrail_quarantines_regardless_of_models(make_telemetry):
    # Collapsed trust under pressure mandates quarantine even if no model agrees.
    recs = [_rec(RiskLevel.MEDIUM, name=n) for n in ("a", "b", "c", "d")]
    decision = _decide(
        make_telemetry,
        recs,
        endpoint_trust_score=0.1,
        adversary_pressure=0.9,
    )
    assert decision.requires_quarantine is True
    assert decision.final_policy is CryptoPolicyName.SESSION_QUARANTINE


def test_low_risk_quiet_council_makes_low_decision(make_telemetry):
    decision = deliberate(make_telemetry(), SecurityCouncil.default()).decision
    assert decision.final_risk_level is RiskLevel.LOW
    assert decision.final_policy is CryptoPolicyName.STANDARD_AES_256_GCM
    assert decision.requires_quarantine is False
    assert decision.human_review_required is False


def test_quarantine_needs_strict_majority(make_telemetry):
    # 2 of 4 quarantine votes on an eligible event → escalate, do NOT quarantine.
    recs = [
        _rec(RiskLevel.CRITICAL, quarantine=True, name="a"),
        _rec(RiskLevel.CRITICAL, quarantine=True, name="b"),
        _rec(RiskLevel.HIGH, name="c"),
        _rec(RiskLevel.HIGH, name="d"),
    ]
    decision = _decide(
        make_telemetry,
        recs,
        suspected_interception=True,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    assert decision.requires_quarantine is False
    assert decision.final_policy is CryptoPolicyName.QUANTUM_ESCALATED_MODE

    # 3 of 4 quarantine votes → strict majority → quarantine.
    recs2 = [
        _rec(RiskLevel.CRITICAL, quarantine=True, name="a"),
        _rec(RiskLevel.CRITICAL, quarantine=True, name="b"),
        _rec(RiskLevel.CRITICAL, quarantine=True, name="c"),
        _rec(RiskLevel.HIGH, name="d"),
    ]
    decision2 = _decide(
        make_telemetry,
        recs2,
        suspected_interception=True,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    assert decision2.requires_quarantine is True
    assert decision2.final_policy is CryptoPolicyName.SESSION_QUARANTINE


def test_decision_is_explainable_and_serialisable(make_telemetry):
    import json

    decision = deliberate(
        make_telemetry(suspected_interception=True), SecurityCouncil.default()
    ).decision
    assert "reasoning engines evaluated" in decision.explanation
    json.dumps(decision.to_dict())
    assert len(decision.recommendations) == 4
