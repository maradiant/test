"""SimulationRunner — run realistic adaptive security sessions.

Modes:
  * normal              — random low-risk baseline session.
  * seeded              — deterministic run from a fixed seed.
  * scenario driven     — bias telemetry with a named :class:`Scenario`.
  * randomized multi    — several sessions, each with its own scenario/seed.

The runner wires together a telemetry simulator, entropy provider, and an
:class:`AdaptiveSecurityOrchestrator`, then advances the lifecycle for N ticks,
collecting the resulting :class:`SecurityDecisionSnapshot` objects.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..audit.logger import AuditLogger
from ..domain.enums import Scenario
from ..domain.models import SecurityDecisionSnapshot
from ..entropy.provider import QuantumEntropyProvider
from ..orchestration.adaptive_security_orchestrator import (
    AdaptiveSecurityOrchestrator,
)
from ..telemetry.simulator import ThreatTelemetrySimulator


@dataclass(slots=True)
class SessionResult:
    """The full outcome of one simulated session."""

    session_id: str
    scenario: Scenario
    seed: Optional[int]
    snapshots: list[SecurityDecisionSnapshot] = field(default_factory=list)
    audit_logger: Optional[AuditLogger] = None

    @property
    def ticks(self) -> int:
        return len(self.snapshots)


class SimulationRunner:
    """Run one or more adaptive security simulation sessions."""

    def run_session(
        self,
        scenario: Scenario = Scenario.LOW_RISK_NORMAL_OPERATION,
        ticks: int = 10,
        seed: Optional[int] = None,
        session_id: Optional[str] = None,
        jsonl_path: Optional[str] = None,
        echo_console: bool = False,
    ) -> SessionResult:
        """Run a single session and return its :class:`SessionResult`."""
        session_id = session_id or f"sess-{uuid.uuid4().hex[:8]}"

        # Derive independent-but-reproducible seeds for telemetry vs entropy.
        telemetry_seed = seed
        entropy_seed = None if seed is None else seed + 1

        simulator = ThreatTelemetrySimulator(
            session_id=session_id, scenario=scenario, seed=telemetry_seed
        )
        entropy = QuantumEntropyProvider(seed=entropy_seed)
        audit = AuditLogger(jsonl_path=jsonl_path, echo_console=echo_console)
        orchestrator = AdaptiveSecurityOrchestrator(
            session_id=session_id,
            entropy_provider=entropy,
            audit_logger=audit,
        )

        result = SessionResult(
            session_id=session_id,
            scenario=scenario,
            seed=seed,
            audit_logger=audit,
        )
        for _ in range(ticks):
            telemetry = simulator.next()
            snapshot = orchestrator.tick(telemetry)
            result.snapshots.append(snapshot)

        return result

    def run_multi(
        self,
        sessions: int = 3,
        ticks: int = 10,
        seed: Optional[int] = None,
        scenarios: Optional[list[Scenario]] = None,
    ) -> list[SessionResult]:
        """Run several randomized sessions, each with its own scenario/seed."""
        scenario_pool = scenarios or list(Scenario)
        results: list[SessionResult] = []
        for i in range(sessions):
            scenario = scenario_pool[i % len(scenario_pool)]
            session_seed = None if seed is None else seed + i * 100
            results.append(
                self.run_session(
                    scenario=scenario,
                    ticks=ticks,
                    seed=session_seed,
                    session_id=f"sess-{i:02d}-{uuid.uuid4().hex[:6]}",
                )
            )
        return results
