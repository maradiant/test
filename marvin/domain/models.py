"""Strongly-typed data models for MARVIN.

These are plain ``dataclasses`` (no third-party runtime dependency) chosen for
clarity and easy JSON serialisation via :func:`to_dict`. Each model corresponds
to a concrete artefact in the Observe → Score → Reason → Select → Rotate →
Apply → Log lifecycle.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from .enums import (
    AdvisorVendor,
    AuditSeverity,
    CryptoPolicyName,
    DataSensitivity,
    EncryptionFamily,
    KeyStatus,
    RecommendationSource,
    RecommendedAction,
    RiskLevel,
)


def utc_now() -> datetime:
    """Timezone-aware UTC timestamp helper."""
    return datetime.now(timezone.utc)


def _serialise(value: Any) -> Any:
    """Recursively convert values into JSON-friendly primitives."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _serialise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialise(v) for v in value]
    return value


def to_jsonable(value: Any) -> Any:
    """Public helper to convert arbitrary values into JSON-friendly primitives."""
    return _serialise(value)


@dataclass(slots=True)
class TelemetrySnapshot:
    """A single observation of simulated communication conditions."""

    session_id: str
    timestamp: datetime
    network_latency_ms: float
    packet_loss_percent: float
    anomaly_score: float            # 0..1
    endpoint_trust_score: float     # 0..1 (1 == fully trusted)
    failed_auth_attempts: int
    geo_velocity_risk: float        # 0..1
    data_sensitivity: DataSensitivity
    suspected_interception: bool
    traffic_volume: float           # relative units (MB/s)
    adversary_pressure: float       # 0..1
    previous_incident_count: int

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))

    def highlights(self) -> str:
        """A compact human-readable summary of the most salient fields."""
        return (
            f"anomaly={self.anomaly_score:.2f} "
            f"trust={self.endpoint_trust_score:.2f} "
            f"failed_auth={self.failed_auth_attempts} "
            f"intercept={'Y' if self.suspected_interception else 'N'} "
            f"sensitivity={self.data_sensitivity.value} "
            f"adv_pressure={self.adversary_pressure:.2f} "
            f"latency={self.network_latency_ms:.0f}ms "
            f"loss={self.packet_loss_percent:.1f}%"
        )


@dataclass(slots=True)
class EntropyPacket:
    """Simulated entropy material. NOT cryptographically certified randomness."""

    entropy_hex: str
    entropy_source: str
    confidence_score: float  # 0..1 simulated "quantum confidence"
    generated_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class ThreatScore:
    """Explainable risk score derived from telemetry."""

    numeric_score: float            # 0..1
    risk_level: RiskLevel
    reasons: list[str]
    recommended_action: RecommendedAction
    confidence: float               # 0..1

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class CryptoPolicyDecision:
    """A selected cryptographic policy plus its rationale."""

    policy_name: CryptoPolicyName
    encryption_family: EncryptionFamily
    key_rotation_interval_seconds: int
    requires_reauthentication: bool
    requires_session_rekey: bool
    requires_quarantine: bool
    rationale: list[str]
    compliance_notes: str
    expected_latency_impact: str  # e.g. "LOW", "MEDIUM", "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class SessionKey:
    """A simulated session key with lineage tracking."""

    key_id: str
    session_id: str
    created_at: datetime
    expires_at: datetime
    policy_name: CryptoPolicyName
    entropy_reference: str
    status: KeyStatus
    lineage_parent_key_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class KeyRotationEvent:
    """Record of a key lifecycle transition during a tick."""

    rotated: bool
    reason: str
    new_key: Optional[SessionKey] = None
    retired_key_id: Optional[str] = None
    quarantined: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class PostureState:
    """The current applied security posture of a session."""

    risk_level: RiskLevel
    active_policy: CryptoPolicyName
    active_key_id: Optional[str]
    reauthentication_required: bool
    quarantined: bool
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class SecurityDecisionSnapshot:
    """The readable result of one orchestration tick — the MARVIN decision."""

    session_id: str
    tick_number: int
    telemetry_summary: str
    risk_level: RiskLevel
    risk_score: float
    selected_policy: CryptoPolicyName
    key_event: KeyRotationEvent
    posture_state: PostureState
    explanation: str
    next_action: str
    # Present only when the multi-model security council governed this tick.
    council_summary: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class AuditEvent:
    """A fully serialisable audit record describing one decision."""

    event_id: str
    timestamp: datetime
    session_id: str
    tick_number: int
    telemetry: dict[str, Any]
    threat_score: dict[str, Any]
    selected_policy: dict[str, Any]
    key_rotation_event: dict[str, Any]
    posture_state: dict[str, Any]
    explanation: str
    # Full council deliberation (advisor recommendations, consensus, governance)
    # when the multi-model council governed this decision; otherwise None.
    council: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


# --------------------------------------------------------------------------- #
# Multi-model security council models                                         #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class AdvisorContext:
    """The controlled, normalized facts presented identically to every advisor.

    Advisors review *the same* facts and MARVIN's deterministic baseline, then
    return an independent structured opinion. ``telemetry`` is retained for the
    offline/simulated advisors that re-derive their own score; ``facts`` is the
    presentation dict shown in audit logs.
    """

    session_id: str
    facts: dict[str, Any]
    baseline_risk_level: RiskLevel
    baseline_score: float
    telemetry: "TelemetrySnapshot"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "facts": _serialise(self.facts),
            "baseline_risk_level": self.baseline_risk_level.value,
            "baseline_score": self.baseline_score,
        }


@dataclass(slots=True)
class SecurityRecommendation:
    """One advisor's structured opinion. Matches the shared council schema."""

    risk_level: RiskLevel
    recommended_policy: CryptoPolicyName
    requires_key_rotation: bool
    requires_reauthentication: bool
    requires_quarantine: bool
    reasoning_summary: str
    confidence: float
    # Provenance / governance metadata (not part of the model-facing schema).
    advisor_name: str = "unknown"
    vendor: AdvisorVendor = AdvisorVendor.MOCK
    model_name: str = "n/a"
    source: RecommendationSource = RecommendationSource.SIMULATED_OFFLINE
    available: bool = True
    error: Optional[str] = None
    latency_ms: float = 0.0

    def schema_dict(self) -> dict[str, Any]:
        """The model-facing portion of the recommendation (the agreed schema)."""
        return {
            "risk_level": self.risk_level.value,
            "recommended_policy": self.recommended_policy.value,
            "requires_key_rotation": self.requires_key_rotation,
            "requires_reauthentication": self.requires_reauthentication,
            "requires_quarantine": self.requires_quarantine,
            "reasoning_summary": self.reasoning_summary,
            "confidence": self.confidence,
        }

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class ConsensusReport:
    """Aggregated view of all advisor recommendations."""

    total_advisors: int
    available_advisors: int
    risk_level_votes: dict[str, int]
    policy_votes: dict[str, int]
    quarantine_votes: int
    key_rotation_votes: int
    reauthentication_votes: int
    majority_risk_level: RiskLevel
    max_risk_level: RiskLevel
    escalation_risk_level: RiskLevel
    highest_confidence_advisor: Optional[str]
    mean_confidence: float
    agreement_ratio: float

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class DisagreementReport:
    """Where and how the advisors disagreed."""

    has_disagreement: bool
    risk_level_spread: int
    quarantine_split: bool
    outliers: list[str]
    human_review_required: bool
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class GuardrailVerdict:
    """Hard, deterministic constraints that override any model opinion."""

    min_risk_level: RiskLevel
    mandatory_quarantine: bool
    quarantine_eligible: bool
    forbid_no_action: bool
    require_key_rotation: bool
    require_reauthentication: bool
    triggered_rules: list[str]

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))


@dataclass(slots=True)
class CouncilDecision:
    """The final, governed MARVIN decision after weighing the council."""

    session_id: str
    final_risk_level: RiskLevel
    final_policy: CryptoPolicyName
    requires_key_rotation: bool
    requires_reauthentication: bool
    requires_quarantine: bool
    audit_severity: AuditSeverity
    conservative_action: bool
    human_review_required: bool
    explanation: str
    recommendations: list[dict[str, Any]]
    consensus: dict[str, Any]
    disagreement: dict[str, Any]
    guardrails: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _serialise(asdict(self))
