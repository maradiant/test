"""Tests for the adaptive crypto policy engine."""

from __future__ import annotations

from marvin.domain.enums import (
    CryptoPolicyName,
    DataSensitivity,
    RecommendedAction,
    RiskLevel,
)
from marvin.domain.models import TelemetrySnapshot, ThreatScore, utc_now
from marvin.policy.crypto_policy_engine import CryptoPolicyEngine


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


def make_score(level: RiskLevel, score: float = 0.5) -> ThreatScore:
    return ThreatScore(
        numeric_score=score,
        risk_level=level,
        reasons=["test"],
        recommended_action=RecommendedAction.MAINTAIN,
        confidence=0.9,
    )


def test_low_risk_selects_standard_policy():
    engine = CryptoPolicyEngine()
    decision = engine.select(make_score(RiskLevel.LOW, 0.1), make_telemetry())
    assert decision.policy_name is CryptoPolicyName.STANDARD_AES_256_GCM
    assert decision.requires_quarantine is False


def test_medium_risk_increases_rotation_frequency():
    engine = CryptoPolicyEngine()
    low = engine.select(make_score(RiskLevel.LOW, 0.1), make_telemetry())
    medium = engine.select(make_score(RiskLevel.MEDIUM, 0.4), make_telemetry())
    assert (
        medium.key_rotation_interval_seconds
        < low.key_rotation_interval_seconds
    )
    assert medium.policy_name is CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION


def test_high_risk_engages_hybrid_pqc_and_reauth():
    engine = CryptoPolicyEngine()
    decision = engine.select(make_score(RiskLevel.HIGH, 0.7), make_telemetry())
    assert decision.policy_name is CryptoPolicyName.HYBRID_POST_QUANTUM_MODE
    assert decision.requires_reauthentication is True


def test_suspected_interception_escalates_protection():
    engine = CryptoPolicyEngine()
    # Medium base risk, but interception present → escalate to at least hybrid PQC.
    decision = engine.select(
        make_score(RiskLevel.MEDIUM, 0.45),
        make_telemetry(suspected_interception=True),
    )
    assert decision.policy_name in {
        CryptoPolicyName.HYBRID_POST_QUANTUM_MODE,
        CryptoPolicyName.QUANTUM_ESCALATED_MODE,
        CryptoPolicyName.SESSION_QUARANTINE,
    }


def test_critical_attack_chain_triggers_quarantine():
    engine = CryptoPolicyEngine()
    decision = engine.select(
        make_score(RiskLevel.CRITICAL, 0.95),
        make_telemetry(
            suspected_interception=True,
            endpoint_trust_score=0.1,
            adversary_pressure=0.95,
        ),
    )
    assert decision.policy_name is CryptoPolicyName.SESSION_QUARANTINE
    assert decision.requires_quarantine is True


def test_high_sensitivity_raises_protection_floor():
    engine = CryptoPolicyEngine()
    # LOW base risk, but restricted data should raise the floor above standard.
    decision = engine.select(
        make_score(RiskLevel.LOW, 0.1),
        make_telemetry(data_sensitivity=DataSensitivity.RESTRICTED),
    )
    assert decision.policy_name is not CryptoPolicyName.STANDARD_AES_256_GCM


def test_degraded_network_prefers_low_latency_cipher():
    engine = CryptoPolicyEngine()
    decision = engine.select(
        make_score(RiskLevel.LOW, 0.1),
        make_telemetry(network_latency_ms=300.0, packet_loss_percent=8.0),
    )
    assert decision.policy_name is CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY
