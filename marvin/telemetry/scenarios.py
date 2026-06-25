"""Named scenario profiles for the telemetry simulator.

Each scenario is a *bias profile*: a set of value ranges and probabilities that
shape the random telemetry generated each tick. Scenarios let us tell a
repeatable story (e.g. a credential-stuffing attack, a suspected interception)
while still allowing seeded randomness for deterministic runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..domain.enums import DataSensitivity, Scenario


@dataclass(frozen=True, slots=True)
class ScenarioProfile:
    """Value ranges and probabilities that bias telemetry generation.

    Ranges are ``(low, high)`` inclusive bounds the simulator samples from.
    Probabilities are 0..1. ``escalates`` indicates whether risk indicators
    should drift upward as the session progresses (used to model an unfolding
    attack chain rather than a static condition).
    """

    anomaly: tuple[float, float] = (0.0, 0.1)
    endpoint_trust: tuple[float, float] = (0.85, 1.0)
    failed_auth: tuple[int, int] = (0, 0)
    geo_velocity_risk: tuple[float, float] = (0.0, 0.1)
    adversary_pressure: tuple[float, float] = (0.0, 0.1)
    network_latency_ms: tuple[float, float] = (10.0, 40.0)
    packet_loss_percent: tuple[float, float] = (0.0, 0.5)
    traffic_volume: tuple[float, float] = (1.0, 10.0)
    previous_incident_count: tuple[int, int] = (0, 0)
    interception_probability: float = 0.0
    spike_probability: float = 0.05
    sensitivity_choices: tuple[DataSensitivity, ...] = (
        DataSensitivity.PUBLIC,
        DataSensitivity.INTERNAL,
    )
    escalates: bool = False
    description: str = ""


# A small registry of hand-tuned scenario profiles. These intentionally read
# like a threat narrative so the simulation tells a clear story.
SCENARIO_PROFILES: dict[Scenario, ScenarioProfile] = {
    Scenario.LOW_RISK_NORMAL_OPERATION: ScenarioProfile(
        description="Healthy session, trusted endpoint, ordinary traffic.",
    ),
    Scenario.CREDENTIAL_STUFFING: ScenarioProfile(
        anomaly=(0.3, 0.6),
        endpoint_trust=(0.3, 0.6),
        failed_auth=(5, 40),
        geo_velocity_risk=(0.4, 0.9),
        adversary_pressure=(0.4, 0.7),
        previous_incident_count=(0, 3),
        spike_probability=0.25,
        sensitivity_choices=(DataSensitivity.INTERNAL, DataSensitivity.CONFIDENTIAL),
        escalates=True,
        description="Repeated failed auth from improbable geo velocity.",
    ),
    Scenario.SUSPECTED_INTERCEPTION: ScenarioProfile(
        anomaly=(0.4, 0.8),
        endpoint_trust=(0.4, 0.7),
        failed_auth=(0, 3),
        geo_velocity_risk=(0.2, 0.6),
        adversary_pressure=(0.5, 0.85),
        network_latency_ms=(40.0, 120.0),
        packet_loss_percent=(0.5, 4.0),
        previous_incident_count=(0, 2),
        interception_probability=0.7,
        spike_probability=0.3,
        sensitivity_choices=(DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED),
        escalates=True,
        description="Signs of a man-in-the-middle: jitter, anomalies, intercept flag.",
    ),
    Scenario.HIGH_VALUE_DATA_TRANSFER: ScenarioProfile(
        anomaly=(0.1, 0.35),
        endpoint_trust=(0.7, 0.95),
        failed_auth=(0, 1),
        adversary_pressure=(0.2, 0.5),
        traffic_volume=(50.0, 200.0),
        sensitivity_choices=(DataSensitivity.RESTRICTED,),
        spike_probability=0.1,
        description="Bulk transfer of restricted data; protection must scale up.",
    ),
    Scenario.DEGRADED_NETWORK: ScenarioProfile(
        anomaly=(0.1, 0.3),
        endpoint_trust=(0.6, 0.9),
        network_latency_ms=(150.0, 400.0),
        packet_loss_percent=(3.0, 12.0),
        adversary_pressure=(0.1, 0.3),
        sensitivity_choices=(DataSensitivity.INTERNAL, DataSensitivity.CONFIDENTIAL),
        spike_probability=0.1,
        description="Poor link quality; latency-aware policy choices matter.",
    ),
    Scenario.CRITICAL_ATTACK_CHAIN: ScenarioProfile(
        anomaly=(0.7, 1.0),
        endpoint_trust=(0.0, 0.3),
        failed_auth=(10, 60),
        geo_velocity_risk=(0.6, 1.0),
        adversary_pressure=(0.8, 1.0),
        network_latency_ms=(60.0, 200.0),
        packet_loss_percent=(2.0, 10.0),
        previous_incident_count=(2, 8),
        interception_probability=0.6,
        spike_probability=0.5,
        sensitivity_choices=(DataSensitivity.RESTRICTED,),
        escalates=True,
        description="Multi-stage active attack: low trust, high pressure, interception.",
    ),
}


def get_profile(scenario: Scenario) -> ScenarioProfile:
    """Return the bias profile for a scenario (defaults to low risk)."""
    return SCENARIO_PROFILES.get(
        scenario, SCENARIO_PROFILES[Scenario.LOW_RISK_NORMAL_OPERATION]
    )
