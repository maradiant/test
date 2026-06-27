"""Shared pytest fixtures for MARVIN tests."""

from __future__ import annotations

import pytest

from marvin.domain.enums import DataSensitivity
from marvin.domain.models import TelemetrySnapshot, utc_now


@pytest.fixture
def make_telemetry():
    """Factory for telemetry snapshots with sensible calm defaults."""

    def _make(**overrides) -> TelemetrySnapshot:
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

    return _make
