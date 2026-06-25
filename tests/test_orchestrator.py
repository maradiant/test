"""Tests for the adaptive security orchestrator and audit logger."""

from __future__ import annotations

from marvin.audit.logger import AuditLogger
from marvin.domain.enums import CryptoPolicyName, RiskLevel, Scenario
from marvin.entropy.provider import QuantumEntropyProvider
from marvin.orchestration.adaptive_security_orchestrator import (
    AdaptiveSecurityOrchestrator,
)
from marvin.telemetry.simulator import ThreatTelemetrySimulator


def build_orchestrator(seed: int = 1):
    audit = AuditLogger()
    entropy = QuantumEntropyProvider(seed=seed)
    orch = AdaptiveSecurityOrchestrator(
        session_id="s", entropy_provider=entropy, audit_logger=audit
    )
    return orch, audit


def test_orchestrator_returns_explainable_snapshot():
    orch, _ = build_orchestrator()
    sim = ThreatTelemetrySimulator("s", Scenario.LOW_RISK_NORMAL_OPERATION, seed=1)
    snapshot = orch.tick(sim.next())
    assert snapshot.tick_number == 1
    assert snapshot.explanation
    assert snapshot.next_action
    assert snapshot.selected_policy is not None
    assert isinstance(snapshot.risk_level, RiskLevel)


def test_audit_logger_records_every_decision():
    orch, audit = build_orchestrator()
    sim = ThreatTelemetrySimulator("s", Scenario.CREDENTIAL_STUFFING, seed=2)
    for _ in range(8):
        orch.tick(sim.next())
    assert len(audit.events) == 8
    # Tick numbers are contiguous and explanations present.
    ticks = [e.tick_number for e in audit.events]
    assert ticks == list(range(1, 9))
    assert all(e.explanation for e in audit.events)


def test_low_risk_session_selects_standard_policy():
    orch, _ = build_orchestrator(seed=5)
    sim = ThreatTelemetrySimulator("s", Scenario.LOW_RISK_NORMAL_OPERATION, seed=5)
    policies = {orch.tick(sim.next()).selected_policy for _ in range(10)}
    # A calm session should predominantly stay on standard baseline encryption.
    assert CryptoPolicyName.STANDARD_AES_256_GCM in policies


def test_critical_attack_chain_quarantines_session():
    orch, _ = build_orchestrator(seed=7)
    sim = ThreatTelemetrySimulator("s", Scenario.CRITICAL_ATTACK_CHAIN, seed=7)
    quarantined = False
    for _ in range(20):
        snap = orch.tick(sim.next())
        if snap.posture_state.quarantined:
            quarantined = True
            break
    assert quarantined is True
    assert orch.posture.quarantined is True


def test_quarantine_is_sticky():
    orch, audit = build_orchestrator(seed=7)
    sim = ThreatTelemetrySimulator("s", Scenario.CRITICAL_ATTACK_CHAIN, seed=7)
    for _ in range(20):
        orch.tick(sim.next())
    # Once quarantined, posture stays quarantined and ticks keep being audited.
    assert orch.posture.quarantined is True
    assert len(audit.events) == 20


def test_suspected_interception_escalates_protection():
    orch, _ = build_orchestrator(seed=3)
    sim = ThreatTelemetrySimulator("s", Scenario.SUSPECTED_INTERCEPTION, seed=3)
    escalated_policies = {
        CryptoPolicyName.HYBRID_POST_QUANTUM_MODE,
        CryptoPolicyName.QUANTUM_ESCALATED_MODE,
        CryptoPolicyName.SESSION_QUARANTINE,
    }
    seen = {orch.tick(sim.next()).selected_policy for _ in range(12)}
    assert seen & escalated_policies
