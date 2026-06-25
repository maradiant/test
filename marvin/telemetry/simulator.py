"""ThreatTelemetrySimulator — produce changing security conditions per tick.

The simulator is the *Observe* stage of MARVIN. It generates baseline low-risk
telemetry, randomly introduces risk spikes, and can be biased by a named
scenario. A seeded ``random.Random`` instance makes runs fully deterministic.
"""

from __future__ import annotations

import random
from typing import Optional

from ..domain.enums import DataSensitivity, Scenario
from ..domain.models import TelemetrySnapshot, utc_now
from .scenarios import ScenarioProfile, get_profile


class ThreatTelemetrySimulator:
    """Generate :class:`TelemetrySnapshot` objects for a single session.

    Parameters
    ----------
    session_id:
        Stable identifier for the simulated session.
    scenario:
        Named scenario that biases telemetry generation.
    seed:
        Optional seed for deterministic, repeatable simulations.
    """

    def __init__(
        self,
        session_id: str,
        scenario: Scenario = Scenario.LOW_RISK_NORMAL_OPERATION,
        seed: Optional[int] = None,
    ) -> None:
        self.session_id = session_id
        self.scenario = scenario
        self._profile: ScenarioProfile = get_profile(scenario)
        self._rng = random.Random(seed)
        self._tick = 0

    @property
    def profile(self) -> ScenarioProfile:
        return self._profile

    def _escalation_factor(self) -> float:
        """How far an escalating scenario has progressed (0..~1).

        Escalating scenarios ramp risk indicators up over the first ~10 ticks
        so an unfolding attack chain looks progressive rather than constant.
        """
        if not self._profile.escalates:
            return 0.0
        return min(1.0, self._tick / 10.0)

    def _sample(self, low: float, high: float, escalate: bool = False) -> float:
        value = self._rng.uniform(low, high)
        if escalate:
            # Bias the value toward the high end as the scenario escalates.
            factor = self._escalation_factor()
            value = value + (high - value) * factor
        return value

    def _sample_int(self, low: int, high: int, escalate: bool = False) -> int:
        if high <= low:
            return low
        value = self._rng.randint(low, high)
        if escalate:
            factor = self._escalation_factor()
            value = int(round(value + (high - value) * factor))
        return value

    def next(self) -> TelemetrySnapshot:
        """Generate the next telemetry snapshot and advance the tick counter."""
        self._tick += 1
        p = self._profile
        spike = self._rng.random() < p.spike_probability
        escalate = p.escalates

        anomaly = self._sample(*p.anomaly, escalate=escalate)
        adversary = self._sample(*p.adversary_pressure, escalate=escalate)
        geo = self._sample(*p.geo_velocity_risk, escalate=escalate)
        trust = self._sample(*p.endpoint_trust)
        failed = self._sample_int(*p.failed_auth, escalate=escalate)
        latency = self._sample(*p.network_latency_ms)
        loss = self._sample(*p.packet_loss_percent)
        traffic = self._sample(*p.traffic_volume)
        incidents = self._sample_int(*p.previous_incident_count)
        intercept = self._rng.random() < p.interception_probability

        if spike:
            # A spike sharply worsens the dominant indicators for one tick.
            anomaly = min(1.0, anomaly + self._rng.uniform(0.2, 0.4))
            adversary = min(1.0, adversary + self._rng.uniform(0.15, 0.35))
            trust = max(0.0, trust - self._rng.uniform(0.1, 0.3))
            failed += self._rng.randint(1, 10)

        sensitivity: DataSensitivity = self._rng.choice(list(p.sensitivity_choices))

        return TelemetrySnapshot(
            session_id=self.session_id,
            timestamp=utc_now(),
            network_latency_ms=round(latency, 2),
            packet_loss_percent=round(max(0.0, loss), 2),
            anomaly_score=round(_clamp01(anomaly), 4),
            endpoint_trust_score=round(_clamp01(trust), 4),
            failed_auth_attempts=max(0, failed),
            geo_velocity_risk=round(_clamp01(geo), 4),
            data_sensitivity=sensitivity,
            suspected_interception=intercept,
            traffic_volume=round(max(0.0, traffic), 2),
            adversary_pressure=round(_clamp01(adversary), 4),
            previous_incident_count=max(0, incidents),
        )


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))
