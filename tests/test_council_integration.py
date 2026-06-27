"""Integration tests: council mode through the orchestrator, runner, and web."""

from __future__ import annotations

from marvin.advisors import SecurityCouncil
from marvin.audit.logger import AuditLogger
from marvin.domain.enums import Scenario
from marvin.entropy.provider import QuantumEntropyProvider
from marvin.orchestration.adaptive_security_orchestrator import (
    AdaptiveSecurityOrchestrator,
)
from marvin.simulation.runner import SimulationRunner
from marvin.telemetry.simulator import ThreatTelemetrySimulator
from marvin.web.server import MarvinHandler


def test_orchestrator_council_mode_populates_snapshot():
    audit = AuditLogger()
    orch = AdaptiveSecurityOrchestrator(
        "s",
        QuantumEntropyProvider(seed=8),
        audit_logger=audit,
        council=SecurityCouncil.default(),
    )
    sim = ThreatTelemetrySimulator("s", Scenario.SUSPECTED_INTERCEPTION, seed=7)
    snap = orch.tick(sim.next())
    assert snap.council_summary is not None
    assert "advisors" in snap.council_summary
    assert len(snap.council_summary["advisors"]) == 4
    # Council deliberation is captured in the audit trail.
    assert audit.events[0].council is not None
    assert "decision" in audit.events[0].council


def test_council_mode_still_logs_every_decision():
    audit = AuditLogger()
    orch = AdaptiveSecurityOrchestrator(
        "s",
        QuantumEntropyProvider(seed=2),
        audit_logger=audit,
        council=SecurityCouncil.default(),
    )
    sim = ThreatTelemetrySimulator("s", Scenario.CREDENTIAL_STUFFING, seed=2)
    for _ in range(6):
        orch.tick(sim.next())
    assert len(audit.events) == 6


def test_baseline_mode_has_no_council_summary():
    orch = AdaptiveSecurityOrchestrator("s", QuantumEntropyProvider(seed=1))
    sim = ThreatTelemetrySimulator("s", Scenario.LOW_RISK_NORMAL_OPERATION, seed=1)
    snap = orch.tick(sim.next())
    assert snap.council_summary is None


def test_runner_council_is_deterministic():
    runner = SimulationRunner()
    a = runner.run_session(
        scenario=Scenario.SUSPECTED_INTERCEPTION, ticks=6, seed=7, council=True
    )
    b = runner.run_session(
        scenario=Scenario.SUSPECTED_INTERCEPTION, ticks=6, seed=7, council=True
    )
    assert [s.risk_level for s in a.snapshots] == [s.risk_level for s in b.snapshots]
    assert [s.selected_policy for s in a.snapshots] == [
        s.selected_policy for s in b.snapshots
    ]
    assert a.council is True
    assert all(s.council_summary is not None for s in a.snapshots)


def test_critical_attack_chain_quarantines_under_council():
    runner = SimulationRunner()
    result = runner.run_session(
        scenario=Scenario.CRITICAL_ATTACK_CHAIN, ticks=20, seed=42, council=True
    )
    assert any(s.posture_state.quarantined for s in result.snapshots)


def test_web_api_council_payload():
    payload = MarvinHandler._run_simulation(
        {"scenario": "SUSPECTED_INTERCEPTION", "ticks": 3, "seed": 7, "council": True}
    )
    assert payload["council"] is True
    first = payload["decisions"][0]
    assert first["council"] is not None
    assert len(first["council"]["advisors"]) == 4
    # The full deliberation is present in the audit records.
    assert payload["audit"][0]["council"] is not None
