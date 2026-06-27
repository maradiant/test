"""escalation_rules — pure helpers for conservative, governed action selection.

These functions encode MARVIN's bias: when in doubt, protect. They are kept
free of side effects so they are trivial to unit-test and reason about.
"""

from __future__ import annotations

from ..domain.enums import AuditSeverity, CryptoPolicyName, RiskLevel

# Lowest audit severity implied by each risk band.
AUDIT_SEVERITY_BY_RISK: dict[RiskLevel, AuditSeverity] = {
    RiskLevel.LOW: AuditSeverity.INFO,
    RiskLevel.MEDIUM: AuditSeverity.NOTICE,
    RiskLevel.HIGH: AuditSeverity.WARNING,
    RiskLevel.CRITICAL: AuditSeverity.CRITICAL,
}


def conservative_policy(
    risk_level: RiskLevel,
    requires_quarantine: bool,
    degraded_network: bool = False,
) -> CryptoPolicyName:
    """Map a governed risk level onto a cryptographic policy.

    Quarantine wins outright. Otherwise the policy scales with risk, with a
    latency-aware swap to ChaCha20 only at the lower bands on degraded links.
    """
    if requires_quarantine:
        return CryptoPolicyName.SESSION_QUARANTINE
    if risk_level is RiskLevel.CRITICAL:
        return CryptoPolicyName.QUANTUM_ESCALATED_MODE
    if risk_level is RiskLevel.HIGH:
        return CryptoPolicyName.HYBRID_POST_QUANTUM_MODE
    if risk_level is RiskLevel.MEDIUM:
        if degraded_network:
            return CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY
        return CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION
    if degraded_network:
        return CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY
    return CryptoPolicyName.STANDARD_AES_256_GCM


def compute_audit_severity(
    risk_level: RiskLevel,
    requires_quarantine: bool,
    human_review_required: bool,
) -> AuditSeverity:
    """Derive audit severity from the final risk and decision context."""
    severity = AUDIT_SEVERITY_BY_RISK[risk_level]
    if requires_quarantine:
        severity = AuditSeverity.CRITICAL
    if human_review_required and severity is AuditSeverity.INFO:
        severity = AuditSeverity.NOTICE
    if human_review_required and severity is AuditSeverity.NOTICE:
        severity = AuditSeverity.WARNING
    return severity
