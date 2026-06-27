"""Enumerations shared across MARVIN.

Keeping these in one place makes the vocabulary of the system explicit:
risk levels, recommended actions, scenarios, cryptographic policies, and key
lifecycle states. Every enum is string-valued so it serialises cleanly into
JSON audit logs.
"""

from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    """Discrete risk bands produced by the scoring engine."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def order(self) -> int:
        """Numeric ordering so risk levels can be compared / escalated."""
        return _RISK_ORDER[self]

    def escalated(self, steps: int = 1) -> "RiskLevel":
        """Return the risk level ``steps`` bands higher, clamped at CRITICAL."""
        target = min(len(_RISK_BY_ORDER) - 1, max(0, self.order + steps))
        return _RISK_BY_ORDER[target]

    @staticmethod
    def max(a: "RiskLevel", b: "RiskLevel") -> "RiskLevel":
        """Return whichever risk level is more severe."""
        return a if a.order >= b.order else b


_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_RISK_BY_ORDER: dict[int, RiskLevel] = {v: k for k, v in _RISK_ORDER.items()}


class RecommendedAction(str, Enum):
    """High-level recommendation attached to a threat score."""

    MAINTAIN = "MAINTAIN"
    INCREASE_ROTATION = "INCREASE_ROTATION"
    ESCALATE_ENCRYPTION = "ESCALATE_ENCRYPTION"
    REAUTHENTICATE = "REAUTHENTICATE"
    QUARANTINE = "QUARANTINE"


class Scenario(str, Enum):
    """Named, manually injectable telemetry scenarios."""

    LOW_RISK_NORMAL_OPERATION = "LOW_RISK_NORMAL_OPERATION"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    SUSPECTED_INTERCEPTION = "SUSPECTED_INTERCEPTION"
    HIGH_VALUE_DATA_TRANSFER = "HIGH_VALUE_DATA_TRANSFER"
    DEGRADED_NETWORK = "DEGRADED_NETWORK"
    CRITICAL_ATTACK_CHAIN = "CRITICAL_ATTACK_CHAIN"


class CryptoPolicyName(str, Enum):
    """Simulated cryptographic policies MARVIN can select."""

    STANDARD_AES_256_GCM = "STANDARD_AES_256_GCM"
    CHACHA20_POLY1305_LOW_LATENCY = "CHACHA20_POLY1305_LOW_LATENCY"
    AES_256_GCM_FREQUENT_ROTATION = "AES_256_GCM_FREQUENT_ROTATION"
    HYBRID_POST_QUANTUM_MODE = "HYBRID_POST_QUANTUM_MODE"
    QUANTUM_ESCALATED_MODE = "QUANTUM_ESCALATED_MODE"
    SESSION_QUARANTINE = "SESSION_QUARANTINE"


class EncryptionFamily(str, Enum):
    """Simulated families of encryption primitives."""

    AES_GCM = "AES_GCM"
    CHACHA20_POLY1305 = "CHACHA20_POLY1305"
    HYBRID_PQC = "HYBRID_PQC"
    QUANTUM_ESCALATED = "QUANTUM_ESCALATED"
    NONE = "NONE"


class KeyStatus(str, Enum):
    """Lifecycle state of a simulated session key."""

    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"


class DataSensitivity(str, Enum):
    """Sensitivity classification of the data flowing through the session."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    MISSION_CRITICAL = "MISSION_CRITICAL"

    @property
    def weight(self) -> float:
        """Normalised 0..1 weight used by the scoring engine."""
        return _SENSITIVITY_WEIGHT[self]


# RESTRICTED and MISSION_CRITICAL both saturate the weight at 1.0; the
# distinction matters for governance guardrails, not for raw scoring.
_SENSITIVITY_WEIGHT: dict[DataSensitivity, float] = {
    DataSensitivity.PUBLIC: 0.0,
    DataSensitivity.INTERNAL: 0.33,
    DataSensitivity.CONFIDENTIAL: 0.66,
    DataSensitivity.RESTRICTED: 1.0,
    DataSensitivity.MISSION_CRITICAL: 1.0,
}


# Data classes that the multi-model security council layer revolves around.


class AdvisorVendor(str, Enum):
    """The independent reasoning engines that sit on the security council."""

    OPENAI = "OPENAI"
    GEMINI = "GEMINI"
    LLAMA = "LLAMA"
    CLAUDE = "CLAUDE"
    MOCK = "MOCK"


class RecommendationSource(str, Enum):
    """Where an advisor's recommendation actually came from."""

    SIMULATED_OFFLINE = "SIMULATED_OFFLINE"          # deterministic local persona
    LIVE_API = "LIVE_API"                            # real model API call
    LIVE_API_FALLBACK_OFFLINE = "LIVE_API_FALLBACK_OFFLINE"  # API failed → offline
    STATIC_STUB = "STATIC_STUB"                      # preset value (tests)


class AuditSeverity(str, Enum):
    """Severity attached to a governed council decision for audit triage."""

    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
