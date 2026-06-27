"""Advisor base classes and the deterministic offline persona engine.

A :class:`SecurityAdvisor` turns an :class:`AdvisorContext` (the controlled
facts) into a :class:`SecurityRecommendation` (the shared schema). The base
class handles timing, error capture, and the offline/online dispatch so concrete
advisors only declare a *persona* (for the simulated path) and optionally
implement ``_advise_online`` (for a real model API).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ..domain.enums import (
    AdvisorVendor,
    CryptoPolicyName,
    RecommendationSource,
    RiskLevel,
)
from ..domain.models import (
    AdvisorContext,
    SecurityRecommendation,
    TelemetrySnapshot,
    ThreatScore,
)
from ..scoring.threat_scoring_engine import ScoringWeights, ThreatScoringEngine

# JSON schema advertised to real model APIs that support structured outputs.
# Mirrors SecurityRecommendation.schema_dict().
RECOMMENDATION_JSON_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "risk_level": {"type": "string", "enum": [r.value for r in RiskLevel]},
        "recommended_policy": {
            "type": "string",
            "enum": [p.value for p in CryptoPolicyName],
        },
        "requires_key_rotation": {"type": "boolean"},
        "requires_reauthentication": {"type": "boolean"},
        "requires_quarantine": {"type": "boolean"},
        "reasoning_summary": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    },
    "required": [
        "risk_level",
        "recommended_policy",
        "requires_key_rotation",
        "requires_reauthentication",
        "requires_quarantine",
        "reasoning_summary",
        "confidence",
    ],
}


def build_advisor_context(
    telemetry: TelemetrySnapshot, baseline: ThreatScore
) -> AdvisorContext:
    """Normalise a telemetry snapshot into the controlled facts shown to advisors."""
    facts = {
        "failed_auth_attempts": telemetry.failed_auth_attempts,
        "endpoint_trust": round(telemetry.endpoint_trust_score, 2),
        "geo_velocity_risk": round(telemetry.geo_velocity_risk, 2),
        "anomaly_score": round(telemetry.anomaly_score, 2),
        "adversary_pressure": round(telemetry.adversary_pressure, 2),
        "data_sensitivity": telemetry.data_sensitivity.value,
        "suspected_interception": telemetry.suspected_interception,
        "packet_loss_percent": round(telemetry.packet_loss_percent, 2),
        "network_latency_ms": round(telemetry.network_latency_ms, 1),
        "previous_incident_count": telemetry.previous_incident_count,
    }
    return AdvisorContext(
        session_id=telemetry.session_id,
        facts=facts,
        baseline_risk_level=baseline.risk_level,
        baseline_score=baseline.numeric_score,
        telemetry=telemetry,
    )


_SYSTEM_PROMPT = (
    "You are an independent cybersecurity advisor on a multi-model security "
    "council. Review the controlled telemetry facts and return a single JSON "
    "object matching the required schema exactly. You only advise; a "
    "deterministic policy engine makes the final decision. Be precise and "
    "conservative when sensitive data or interception is involved."
)


def render_prompt(context: AdvisorContext) -> tuple[str, str]:
    """Build (system, user) prompt strings for a real model API call."""
    import json as _json

    facts = _json.dumps(context.facts, indent=2)
    user = (
        "Controlled telemetry facts:\n"
        f"{facts}\n\n"
        f"MARVIN deterministic baseline risk: {context.baseline_risk_level.value} "
        f"(score {context.baseline_score:.2f}).\n\n"
        "Return ONLY a JSON object with keys: risk_level, recommended_policy, "
        "requires_key_rotation, requires_reauthentication, requires_quarantine, "
        "reasoning_summary, confidence."
    )
    return _SYSTEM_PROMPT, user


def parse_recommendation(
    payload: dict,
    *,
    advisor_name: str,
    vendor: AdvisorVendor,
    model_name: str,
) -> SecurityRecommendation:
    """Coerce a model's JSON payload into a validated SecurityRecommendation."""
    return SecurityRecommendation(
        risk_level=RiskLevel(payload["risk_level"]),
        recommended_policy=CryptoPolicyName(payload["recommended_policy"]),
        requires_key_rotation=bool(payload["requires_key_rotation"]),
        requires_reauthentication=bool(payload["requires_reauthentication"]),
        requires_quarantine=bool(payload["requires_quarantine"]),
        reasoning_summary=str(payload["reasoning_summary"]),
        confidence=float(payload["confidence"]),
        advisor_name=advisor_name,
        vendor=vendor,
        model_name=model_name,
        source=RecommendationSource.LIVE_API,
    )


@dataclass(frozen=True, slots=True)
class AdvisorPersona:
    """Tuning that gives each offline advisor a distinct, deterministic character.

    ``weights`` re-tune the shared scorer so advisors weigh signals differently
    (genuine independence). ``escalation_bias`` lets conservative advisors push
    the risk band up when a real threat is present. The eagerness flags shape the
    recommended actions; ``confidence_center`` anchors the reported confidence.
    """

    weights: ScoringWeights = field(default_factory=ScoringWeights)
    escalation_bias: int = 0
    quarantine_eager: bool = False
    rotate_eager: bool = False
    reauth_eager: bool = False
    confidence_center: float = 0.8
    flavor: str = ""


def _persona_policy(level: RiskLevel, quarantine: bool) -> CryptoPolicyName:
    if quarantine:
        return CryptoPolicyName.SESSION_QUARANTINE
    if level is RiskLevel.CRITICAL:
        return CryptoPolicyName.QUANTUM_ESCALATED_MODE
    if level is RiskLevel.HIGH:
        return CryptoPolicyName.HYBRID_POST_QUANTUM_MODE
    if level is RiskLevel.MEDIUM:
        return CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION
    return CryptoPolicyName.STANDARD_AES_256_GCM


class SecurityAdvisor(ABC):
    """Base class for every council advisor."""

    vendor: AdvisorVendor = AdvisorVendor.MOCK
    model_name: str = "n/a"
    name: str = "advisor"
    persona: AdvisorPersona = AdvisorPersona()

    def __init__(self, online: bool = False) -> None:
        # Offline (simulated persona) is the default so the council runs with no
        # network access. online=True opts into a real API call when configured.
        self.online = online

    def advise(self, context: AdvisorContext) -> SecurityRecommendation:
        """Return a recommendation, timing the call and capturing any error."""
        started = time.perf_counter()
        error: Optional[str] = None
        source = RecommendationSource.SIMULATED_OFFLINE
        if self.online:
            try:
                rec = self._advise_online(context)
                rec.latency_ms = round((time.perf_counter() - started) * 1000, 2)
                return rec
            except Exception as exc:  # noqa: BLE001 - degrade gracefully
                error = f"{type(exc).__name__}: {exc}"
                source = RecommendationSource.LIVE_API_FALLBACK_OFFLINE
        rec = self._advise_offline(context)
        rec.source = source
        rec.error = error
        rec.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return rec

    # -- offline (deterministic, simulated) path ---------------------------- #

    def _advise_offline(self, context: AdvisorContext) -> SecurityRecommendation:
        persona = self.persona
        telemetry = context.telemetry
        score = ThreatScoringEngine(persona.weights).score(telemetry)
        level = score.risk_level

        threat_present = (
            level.order >= RiskLevel.MEDIUM.order or telemetry.suspected_interception
        )
        if persona.escalation_bias and threat_present:
            level = level.escalated(persona.escalation_bias)

        requires_quarantine = (
            persona.quarantine_eager
            and level is RiskLevel.CRITICAL
            and (
                telemetry.suspected_interception
                or telemetry.endpoint_trust_score <= 0.3
                or telemetry.data_sensitivity.weight >= 1.0
            )
        )
        requires_key_rotation = (
            persona.rotate_eager or level.order >= RiskLevel.MEDIUM.order
        )
        requires_reauth = (
            persona.reauth_eager
            or telemetry.failed_auth_attempts >= 5
            or level.order >= RiskLevel.HIGH.order
        )
        policy = _persona_policy(level, requires_quarantine)
        confidence = self._confidence(persona, score)
        reasoning = self._summary(persona, score, level, requires_quarantine)

        return SecurityRecommendation(
            risk_level=level,
            recommended_policy=policy,
            requires_key_rotation=requires_key_rotation,
            requires_reauthentication=requires_reauth,
            requires_quarantine=requires_quarantine,
            reasoning_summary=reasoning,
            confidence=confidence,
            advisor_name=self.name,
            vendor=self.vendor,
            model_name=self.model_name,
            source=RecommendationSource.SIMULATED_OFFLINE,
        )

    @staticmethod
    def _confidence(persona: AdvisorPersona, score: ThreatScore) -> float:
        # Clearer signals (score far from the 0.5 midpoint) raise confidence;
        # noisy telemetry (low score confidence) lowers it slightly.
        clarity = abs(score.numeric_score - 0.5) * 0.2
        noise_penalty = (0.95 - score.confidence) * 0.5
        value = persona.confidence_center + clarity - noise_penalty
        return round(min(0.99, max(0.5, value)), 2)

    @staticmethod
    def _summary(
        persona: AdvisorPersona,
        score: ThreatScore,
        level: RiskLevel,
        quarantine: bool,
    ) -> str:
        drivers = "; ".join(score.reasons[:3])
        action = "recommends quarantine" if quarantine else f"assesses {level.value} risk"
        flavor = (persona.flavor + " ").lstrip()
        return f"{flavor}{action.capitalize()}. Drivers: {drivers}"

    # -- online (real API) path --------------------------------------------- #

    @abstractmethod
    def _advise_online(self, context: AdvisorContext) -> SecurityRecommendation:
        """Call the real model API. Implemented by concrete advisors."""
        raise NotImplementedError


class StaticAdvisor(SecurityAdvisor):
    """A preset advisor that always returns a fixed recommendation (for tests)."""

    vendor = AdvisorVendor.MOCK

    def __init__(self, name: str, recommendation: SecurityRecommendation) -> None:
        super().__init__(online=False)
        self.name = name
        self._recommendation = recommendation

    def advise(self, context: AdvisorContext) -> SecurityRecommendation:
        rec = self._recommendation
        rec.advisor_name = self.name
        rec.source = RecommendationSource.STATIC_STUB
        return rec

    def _advise_online(self, context: AdvisorContext) -> SecurityRecommendation:  # pragma: no cover
        raise NotImplementedError
