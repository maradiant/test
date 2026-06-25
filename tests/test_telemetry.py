"""Tests for the threat telemetry simulator."""

from __future__ import annotations

from marvin.domain.enums import DataSensitivity, Scenario
from marvin.domain.models import TelemetrySnapshot
from marvin.telemetry.simulator import ThreatTelemetrySimulator


def test_low_risk_scenario_stays_calm():
    sim = ThreatTelemetrySimulator("s1", Scenario.LOW_RISK_NORMAL_OPERATION, seed=1)
    samples = [sim.next() for _ in range(20)]
    # Baseline operation should keep anomaly and adversary pressure low on average.
    avg_anomaly = sum(s.anomaly_score for s in samples) / len(samples)
    assert avg_anomaly < 0.25
    assert all(isinstance(s, TelemetrySnapshot) for s in samples)
    assert all(s.session_id == "s1" for s in samples)


def test_seeded_simulation_is_repeatable():
    a = ThreatTelemetrySimulator("s", Scenario.CRITICAL_ATTACK_CHAIN, seed=42)
    b = ThreatTelemetrySimulator("s", Scenario.CRITICAL_ATTACK_CHAIN, seed=42)
    for _ in range(15):
        ta, tb = a.next(), b.next()
        assert ta.anomaly_score == tb.anomaly_score
        assert ta.failed_auth_attempts == tb.failed_auth_attempts
        assert ta.suspected_interception == tb.suspected_interception
        assert ta.data_sensitivity == tb.data_sensitivity


def test_critical_scenario_is_high_risk_on_average():
    sim = ThreatTelemetrySimulator("s", Scenario.CRITICAL_ATTACK_CHAIN, seed=3)
    samples = [sim.next() for _ in range(20)]
    avg_anomaly = sum(s.anomaly_score for s in samples) / len(samples)
    avg_pressure = sum(s.adversary_pressure for s in samples) / len(samples)
    assert avg_anomaly > 0.6
    assert avg_pressure > 0.6


def test_high_value_transfer_uses_restricted_data():
    sim = ThreatTelemetrySimulator("s", Scenario.HIGH_VALUE_DATA_TRANSFER, seed=5)
    samples = [sim.next() for _ in range(10)]
    assert all(s.data_sensitivity is DataSensitivity.RESTRICTED for s in samples)


def test_values_are_clamped_to_valid_ranges():
    sim = ThreatTelemetrySimulator("s", Scenario.CRITICAL_ATTACK_CHAIN, seed=9)
    for _ in range(30):
        t = sim.next()
        assert 0.0 <= t.anomaly_score <= 1.0
        assert 0.0 <= t.endpoint_trust_score <= 1.0
        assert 0.0 <= t.adversary_pressure <= 1.0
        assert 0.0 <= t.geo_velocity_risk <= 1.0
        assert t.failed_auth_attempts >= 0
        assert t.packet_loss_percent >= 0.0
