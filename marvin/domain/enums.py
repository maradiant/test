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


_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


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

    @property
    def weight(self) -> float:
        """Normalised 0..1 weight used by the scoring engine."""
        return _SENSITIVITY_WEIGHT[self]


_SENSITIVITY_WEIGHT: dict[DataSensitivity, float] = {
    DataSensitivity.PUBLIC: 0.0,
    DataSensitivity.INTERNAL: 0.33,
    DataSensitivity.CONFIDENTIAL: 0.66,
    DataSensitivity.RESTRICTED: 1.0,
}
