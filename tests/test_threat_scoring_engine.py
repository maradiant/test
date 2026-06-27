"""Tests for the explainable threat scoring engine."""

from __future__ import annotations

from marvin.domain.enums import DataSensitivity, RiskLevel
from marvin.domain.models import TelemetrySnapshot, utc_now
from marvin.scoring.threat_scoring_engine import ScoringWeights, ThreatScoringEngine


def make_telemetry(**overrides) -> TelemetrySnapshot:
    base = dict(
        session_id="s",
        timestamp=utc_now(),
        network_latency_ms=20.0,
        packet_loss_percent=0.1,
        anomaly_score=0.05,
        endpoint_trust_score=0.95,
        failed_auth_attempts=0,
        geo_velocity_risk=0.05,
        data_sensitivity=DataSensitivity.PUBLIC,
        suspected_interception=False,
        traffic_volume=5.0,
        adversary_pressure=0.05,
        previous_incident_count=0,
    )
    base.update(overrides)
    return TelemetrySnapshot(**base)


def test_low_risk_telemetry_scores_low():
    engine = ThreatScoringEngine()
    score = engine.score(make_telemetry())
    assert score.risk_level is RiskLevel.LOW
    assert score.numeric_score <= 0.25
    assert score.reasons  # always explainable


def test_score_always_includes_reasons():
    engine = ThreatScoringEngine()
    score = engine.score(make_telemetry(anomaly_score=0.7, adversary_pressure=0.6))
    assert any("anomaly" in r.lower() for r in score.reasons)
    assert any("adversary" in r.lower() for r in score.reasons)


def test_suspected_interception_floors_risk_to_high():
    engine = ThreatScoringEngine()
    # Otherwise-calm telemetry, but interception is flagged.
    score = engine.score(make_telemetry(suspected_interception=True))
    assert score.risk_level.order >= RiskLevel.HIGH.order


def test_critical_attack_telemetry_scores_critical():
    engine = ThreatScoringEngine()
    score = engine.score(
        make_telemetry(
            anomaly_score=0.95,
            endpoint_trust_score=0.05,
            failed_auth_attempts=30,
            geo_velocity_risk=0.9,
            data_sensitivity=DataSensitivity.RESTRICTED,
            suspected_interception=True,
            adversary_pressure=0.95,
            previous_incident_count=5,
        )
    )
    assert score.risk_level is RiskLevel.CRITICAL


def test_high_sensitivity_increases_score():
    engine = ThreatScoringEngine()
    low = engine.score(make_telemetry(data_sensitivity=DataSensitivity.PUBLIC))
    high = engine.score(make_telemetry(data_sensitivity=DataSensitivity.RESTRICTED))
    assert high.numeric_score > low.numeric_score


def test_tunable_weights_change_outcome():
    telemetry = make_telemetry(anomaly_score=0.8)
    default = ThreatScoringEngine().score(telemetry)
    heavy = ThreatScoringEngine(ScoringWeights(anomaly_score=1.0)).score(telemetry)
    assert heavy.numeric_score >= default.numeric_score


def test_confidence_drops_on_degraded_network():
    engine = ThreatScoringEngine()
    clean = engine.score(make_telemetry(network_latency_ms=10.0, packet_loss_percent=0.0))
    noisy = engine.score(
        make_telemetry(network_latency_ms=400.0, packet_loss_percent=12.0)
    )
    assert noisy.confidence < clean.confidence
