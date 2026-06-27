"""Tests for the deterministic governance guardrails and escalation rules."""

from __future__ import annotations

from marvin.domain.enums import (
    AuditSeverity,
    CryptoPolicyName,
    DataSensitivity,
    RiskLevel,
)
from marvin.governance import PolicyGuardrails, compute_audit_severity, conservative_policy


def test_interception_on_sensitive_data_forbids_inaction(make_telemetry):
    t = make_telemetry(
        suspected_interception=True, data_sensitivity=DataSensitivity.RESTRICTED
    )
    verdict = PolicyGuardrails().evaluate(t)
    assert verdict.forbid_no_action is True
    assert verdict.quarantine_eligible is True
    assert verdict.require_key_rotation is True
    assert verdict.min_risk_level.order >= RiskLevel.HIGH.order
    assert "INTERCEPTION_ON_SENSITIVE_DATA" in verdict.triggered_rules


def test_mission_critical_counts_as_sensitive(make_telemetry):
    t = make_telemetry(
        suspected_interception=True,
        data_sensitivity=DataSensitivity.MISSION_CRITICAL,
    )
    verdict = PolicyGuardrails().evaluate(t)
    assert verdict.quarantine_eligible is True
    assert "MISSION_CRITICAL_DATA" in verdict.triggered_rules


def test_collapsed_trust_under_pressure_mandates_quarantine(make_telemetry):
    t = make_telemetry(endpoint_trust_score=0.1, adversary_pressure=0.9)
    verdict = PolicyGuardrails().evaluate(t)
    assert verdict.mandatory_quarantine is True
    assert verdict.min_risk_level is RiskLevel.CRITICAL


def test_auth_burst_requires_reauth(make_telemetry):
    t = make_telemetry(failed_auth_attempts=15)
    verdict = PolicyGuardrails().evaluate(t)
    assert verdict.require_reauthentication is True
    assert verdict.forbid_no_action is True
    assert "AUTH_BURST" in verdict.triggered_rules


def test_calm_telemetry_triggers_no_guardrails(make_telemetry):
    verdict = PolicyGuardrails().evaluate(make_telemetry())
    assert verdict.triggered_rules == []
    assert verdict.min_risk_level is RiskLevel.LOW
    assert verdict.mandatory_quarantine is False
    assert verdict.forbid_no_action is False


def test_conservative_policy_mapping():
    assert (
        conservative_policy(RiskLevel.LOW, False)
        is CryptoPolicyName.STANDARD_AES_256_GCM
    )
    assert (
        conservative_policy(RiskLevel.MEDIUM, False)
        is CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION
    )
    assert (
        conservative_policy(RiskLevel.HIGH, False)
        is CryptoPolicyName.HYBRID_POST_QUANTUM_MODE
    )
    assert (
        conservative_policy(RiskLevel.CRITICAL, False)
        is CryptoPolicyName.QUANTUM_ESCALATED_MODE
    )
    # Quarantine wins regardless of risk.
    assert (
        conservative_policy(RiskLevel.HIGH, True)
        is CryptoPolicyName.SESSION_QUARANTINE
    )
    # Degraded network prefers low-latency cipher at the lower bands.
    assert (
        conservative_policy(RiskLevel.MEDIUM, False, degraded_network=True)
        is CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY
    )


def test_audit_severity_escalates_on_quarantine_and_review():
    assert compute_audit_severity(RiskLevel.LOW, False, False) is AuditSeverity.INFO
    assert (
        compute_audit_severity(RiskLevel.HIGH, False, False) is AuditSeverity.WARNING
    )
    assert (
        compute_audit_severity(RiskLevel.MEDIUM, True, False)
        is AuditSeverity.CRITICAL
    )
    # Human review nudges an otherwise-low severity upward.
    assert compute_audit_severity(RiskLevel.LOW, False, True) is AuditSeverity.NOTICE
