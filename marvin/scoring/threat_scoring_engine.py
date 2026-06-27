"""ThreatScoringEngine — turn telemetry into an explainable risk score.

This is the *Score* stage. It uses a transparent weighted-sum model: each
contributing signal is normalised to 0..1, multiplied by a tunable weight, and
summed into a 0..1 ``numeric_score`` that maps onto a :class:`RiskLevel`. Every
signal that meaningfully contributes is recorded as a human-readable reason so
the score is fully explainable.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.enums import RecommendedAction, RiskLevel
from ..domain.models import ThreatScore, TelemetrySnapshot


@dataclass(slots=True)
class ScoringWeights:
    """Tunable contribution weights for each risk signal.

    Weights need not sum to 1; the engine normalises by the total weight so the
    final score always lands in 0..1. Defaults emphasise interception and
    adversary pressure, which are the strongest escalation drivers.
    """

    anomaly_score: float = 0.18
    endpoint_trust: float = 0.15           # applied to (1 - trust)
    failed_auth_attempts: float = 0.13
    suspected_interception: float = 0.20
    data_sensitivity: float = 0.10
    adversary_pressure: float = 0.14
    previous_incident_count: float = 0.05
    geo_velocity_risk: float = 0.05

    def total(self) -> float:
        return (
            self.anomaly_score
            + self.endpoint_trust
            + self.failed_auth_attempts
            + self.suspected_interception
            + self.data_sensitivity
            + self.adversary_pressure
            + self.previous_incident_count
            + self.geo_velocity_risk
        )


# Thresholds mapping the normalised numeric score onto discrete risk bands.
LOW_MAX = 0.25
MEDIUM_MAX = 0.50
HIGH_MAX = 0.75


def _normalise_failed_auth(attempts: int) -> float:
    """Map failed-auth counts onto 0..1 (saturates at 10 attempts)."""
    return min(1.0, attempts / 10.0)


def _normalise_incidents(count: int) -> float:
    """Map prior-incident counts onto 0..1 (saturates at 5)."""
    return min(1.0, count / 5.0)


class ThreatScoringEngine:
    """Compute an explainable :class:`ThreatScore` from telemetry."""

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self.weights = weights or ScoringWeights()

    def score(self, telemetry: TelemetrySnapshot) -> ThreatScore:
        w = self.weights
        reasons: list[str] = []

        # Each contribution is (normalised_signal * weight).
        contributions: dict[str, float] = {}

        contributions["anomaly"] = telemetry.anomaly_score * w.anomaly_score
        if telemetry.anomaly_score >= 0.5:
            reasons.append(
                f"Elevated anomaly score ({telemetry.anomaly_score:.2f})."
            )

        distrust = 1.0 - telemetry.endpoint_trust_score
        contributions["endpoint_trust"] = distrust * w.endpoint_trust
        if telemetry.endpoint_trust_score <= 0.5:
            reasons.append(
                f"Low endpoint trust ({telemetry.endpoint_trust_score:.2f})."
            )

        fa = _normalise_failed_auth(telemetry.failed_auth_attempts)
        contributions["failed_auth"] = fa * w.failed_auth_attempts
        if telemetry.failed_auth_attempts >= 5:
            reasons.append(
                f"{telemetry.failed_auth_attempts} failed auth attempts "
                "(possible credential attack)."
            )

        intercept = 1.0 if telemetry.suspected_interception else 0.0
        contributions["interception"] = intercept * w.suspected_interception
        if telemetry.suspected_interception:
            reasons.append("Suspected interception flagged on the channel.")

        sens = telemetry.data_sensitivity.weight
        contributions["data_sensitivity"] = sens * w.data_sensitivity
        if sens >= 0.66:
            reasons.append(
                f"High data sensitivity ({telemetry.data_sensitivity.value})."
            )

        contributions["adversary_pressure"] = (
            telemetry.adversary_pressure * w.adversary_pressure
        )
        if telemetry.adversary_pressure >= 0.5:
            reasons.append(
                f"High adversary pressure ({telemetry.adversary_pressure:.2f})."
            )

        inc = _normalise_incidents(telemetry.previous_incident_count)
        contributions["incidents"] = inc * w.previous_incident_count
        if telemetry.previous_incident_count >= 2:
            reasons.append(
                f"{telemetry.previous_incident_count} prior incidents on session."
            )

        contributions["geo_velocity"] = (
            telemetry.geo_velocity_risk * w.geo_velocity_risk
        )
        if telemetry.geo_velocity_risk >= 0.5:
            reasons.append(
                f"Improbable geo-velocity ({telemetry.geo_velocity_risk:.2f})."
            )

        numeric_score = sum(contributions.values()) / w.total()
        numeric_score = round(min(1.0, max(0.0, numeric_score)), 4)

        risk_level = self._risk_level(numeric_score)

        # Suspected interception is severe enough to floor the risk at HIGH.
        if telemetry.suspected_interception and risk_level.order < RiskLevel.HIGH.order:
            risk_level = RiskLevel.HIGH
            reasons.append("Risk floored to HIGH due to suspected interception.")

        if not reasons:
            reasons.append("All signals within normal baseline ranges.")

        recommended_action = self._recommend(risk_level, telemetry)
        confidence = self._confidence(telemetry)

        return ThreatScore(
            numeric_score=numeric_score,
            risk_level=risk_level,
            reasons=reasons,
            recommended_action=recommended_action,
            confidence=confidence,
        )

    @staticmethod
    def _risk_level(score: float) -> RiskLevel:
        if score <= LOW_MAX:
            return RiskLevel.LOW
        if score <= MEDIUM_MAX:
            return RiskLevel.MEDIUM
        if score <= HIGH_MAX:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    @staticmethod
    def _recommend(
        risk_level: RiskLevel, telemetry: TelemetrySnapshot
    ) -> RecommendedAction:
        if risk_level is RiskLevel.CRITICAL:
            return RecommendedAction.QUARANTINE
        if risk_level is RiskLevel.HIGH:
            if telemetry.failed_auth_attempts >= 5:
                return RecommendedAction.REAUTHENTICATE
            return RecommendedAction.ESCALATE_ENCRYPTION
        if risk_level is RiskLevel.MEDIUM:
            return RecommendedAction.INCREASE_ROTATION
        return RecommendedAction.MAINTAIN

    @staticmethod
    def _confidence(telemetry: TelemetrySnapshot) -> float:
        """Confidence drops when the network is degraded (noisier signals)."""
        degradation = min(
            1.0,
            telemetry.packet_loss_percent / 15.0
            + telemetry.network_latency_ms / 800.0,
        )
        return round(max(0.5, 0.95 - 0.3 * degradation), 4)
