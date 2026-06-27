"""CryptoPolicyEngine — select an adaptive cryptographic policy.

This is the *Reason* and *Select Policy* stage. Given a threat score and the
underlying telemetry, the engine chooses one of several simulated policies and
explains why. Selection is driven primarily by risk level, then refined by
strong signals (suspected interception, data sensitivity, network conditions).

NOTE: The "policies" are descriptive simulations. No real encryption is
performed — the prototype models the *decision logic* of an orchestrator.
"""

from __future__ import annotations

from ..domain.enums import (
    CryptoPolicyName,
    EncryptionFamily,
    RiskLevel,
)
from ..domain.models import CryptoPolicyDecision, ThreatScore, TelemetrySnapshot


# Base templates for each simulated policy. The engine starts from a template
# and may adjust the rotation interval based on live conditions.
_POLICY_TEMPLATES: dict[CryptoPolicyName, dict] = {
    CryptoPolicyName.STANDARD_AES_256_GCM: {
        "encryption_family": EncryptionFamily.AES_GCM,
        "key_rotation_interval_seconds": 3600,
        "requires_reauthentication": False,
        "requires_session_rekey": False,
        "requires_quarantine": False,
        "compliance_notes": "Baseline AEAD; suitable for routine traffic.",
        "expected_latency_impact": "LOW",
    },
    CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY: {
        "encryption_family": EncryptionFamily.CHACHA20_POLY1305,
        "key_rotation_interval_seconds": 1800,
        "requires_reauthentication": False,
        "requires_session_rekey": False,
        "requires_quarantine": False,
        "compliance_notes": "Software-friendly AEAD favoured on degraded links.",
        "expected_latency_impact": "LOW",
    },
    CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION: {
        "encryption_family": EncryptionFamily.AES_GCM,
        "key_rotation_interval_seconds": 300,
        "requires_reauthentication": False,
        "requires_session_rekey": True,
        "requires_quarantine": False,
        "compliance_notes": "Frequent rekeying shrinks key exposure window.",
        "expected_latency_impact": "MEDIUM",
    },
    CryptoPolicyName.HYBRID_POST_QUANTUM_MODE: {
        "encryption_family": EncryptionFamily.HYBRID_PQC,
        "key_rotation_interval_seconds": 120,
        "requires_reauthentication": True,
        "requires_session_rekey": True,
        "requires_quarantine": False,
        "compliance_notes": "Simulated classical+PQC hybrid; reauth enforced.",
        "expected_latency_impact": "MEDIUM",
    },
    CryptoPolicyName.QUANTUM_ESCALATED_MODE: {
        "encryption_family": EncryptionFamily.QUANTUM_ESCALATED,
        "key_rotation_interval_seconds": 30,
        "requires_reauthentication": True,
        "requires_session_rekey": True,
        "requires_quarantine": False,
        "compliance_notes": "Maximum simulated protection; aggressive rekeying.",
        "expected_latency_impact": "HIGH",
    },
    CryptoPolicyName.SESSION_QUARANTINE: {
        "encryption_family": EncryptionFamily.NONE,
        "key_rotation_interval_seconds": 0,
        "requires_reauthentication": True,
        "requires_session_rekey": True,
        "requires_quarantine": True,
        "compliance_notes": "Session isolated pending investigation.",
        "expected_latency_impact": "HIGH",
    },
}


class CryptoPolicyEngine:
    """Choose a :class:`CryptoPolicyDecision` from risk and telemetry."""

    def decision_for(
        self,
        policy_name: CryptoPolicyName,
        telemetry: TelemetrySnapshot,
        rationale: list[str] | None = None,
    ) -> CryptoPolicyDecision:
        """Build a full :class:`CryptoPolicyDecision` for an explicitly chosen policy.

        Used by the governed council pipeline, where the final policy *name* is
        decided deterministically and we just need the concrete policy fields.
        """
        return self._build_decision(policy_name, telemetry, list(rationale or []))

    def select(
        self, threat: ThreatScore, telemetry: TelemetrySnapshot
    ) -> CryptoPolicyDecision:
        rationale: list[str] = []
        policy_name = self._base_policy_for_risk(threat.risk_level, rationale)

        # Strong overriding signals can escalate beyond the base risk mapping.
        policy_name = self._apply_signal_overrides(
            policy_name, threat, telemetry, rationale
        )

        decision = self._build_decision(policy_name, telemetry, rationale)
        return decision

    @staticmethod
    def _base_policy_for_risk(
        risk_level: RiskLevel, rationale: list[str]
    ) -> CryptoPolicyName:
        if risk_level is RiskLevel.LOW:
            rationale.append("LOW risk: standard baseline encryption is sufficient.")
            return CryptoPolicyName.STANDARD_AES_256_GCM
        if risk_level is RiskLevel.MEDIUM:
            rationale.append("MEDIUM risk: shorten key lifetime via frequent rotation.")
            return CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION
        if risk_level is RiskLevel.HIGH:
            rationale.append(
                "HIGH risk: engage hybrid post-quantum mode and require reauth."
            )
            return CryptoPolicyName.HYBRID_POST_QUANTUM_MODE
        rationale.append("CRITICAL risk: escalate to maximum protection.")
        return CryptoPolicyName.QUANTUM_ESCALATED_MODE

    def _apply_signal_overrides(
        self,
        policy_name: CryptoPolicyName,
        threat: ThreatScore,
        telemetry: TelemetrySnapshot,
        rationale: list[str],
    ) -> CryptoPolicyName:
        # Suspected interception strongly escalates protection.
        if telemetry.suspected_interception:
            if threat.risk_level is RiskLevel.CRITICAL:
                rationale.append(
                    "Suspected interception under CRITICAL risk: quarantine session."
                )
                return CryptoPolicyName.SESSION_QUARANTINE
            rationale.append(
                "Suspected interception: escalate to hybrid post-quantum mode."
            )
            policy_name = _max_policy(policy_name, CryptoPolicyName.HYBRID_POST_QUANTUM_MODE)

        # Critical risk with very low trust or heavy attack pressure → quarantine.
        if threat.risk_level is RiskLevel.CRITICAL and (
            telemetry.endpoint_trust_score <= 0.2
            or telemetry.adversary_pressure >= 0.9
        ):
            rationale.append(
                "CRITICAL risk with collapsed trust / extreme pressure: quarantine."
            )
            return CryptoPolicyName.SESSION_QUARANTINE

        # High data sensitivity raises the floor of protection.
        if telemetry.data_sensitivity.weight >= 1.0:
            rationale.append(
                "Restricted data sensitivity: raise protection floor to "
                "frequent rotation."
            )
            policy_name = _max_policy(
                policy_name, CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION
            )

        # Degraded network at low/medium risk favours a low-latency cipher.
        degraded = (
            telemetry.network_latency_ms >= 150.0
            or telemetry.packet_loss_percent >= 3.0
        )
        if degraded and policy_name in {
            CryptoPolicyName.STANDARD_AES_256_GCM,
            CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION,
        }:
            rationale.append(
                "Degraded network: prefer low-latency ChaCha20-Poly1305."
            )
            policy_name = CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY

        return policy_name

    def _build_decision(
        self,
        policy_name: CryptoPolicyName,
        telemetry: TelemetrySnapshot,
        rationale: list[str],
    ) -> CryptoPolicyDecision:
        template = _POLICY_TEMPLATES[policy_name]
        rotation = template["key_rotation_interval_seconds"]

        # Restricted data tightens rotation further (but never on quarantine).
        if (
            telemetry.data_sensitivity.weight >= 1.0
            and rotation > 60
            and not template["requires_quarantine"]
        ):
            rotation = max(60, rotation // 2)
            rationale.append("Restricted data: halve rotation interval.")

        return CryptoPolicyDecision(
            policy_name=policy_name,
            encryption_family=template["encryption_family"],
            key_rotation_interval_seconds=rotation,
            requires_reauthentication=template["requires_reauthentication"],
            requires_session_rekey=template["requires_session_rekey"],
            requires_quarantine=template["requires_quarantine"],
            rationale=rationale,
            compliance_notes=template["compliance_notes"],
            expected_latency_impact=template["expected_latency_impact"],
        )


# Strength ordering used when "raising the floor" of a policy choice.
_POLICY_STRENGTH: dict[CryptoPolicyName, int] = {
    CryptoPolicyName.CHACHA20_POLY1305_LOW_LATENCY: 0,
    CryptoPolicyName.STANDARD_AES_256_GCM: 1,
    CryptoPolicyName.AES_256_GCM_FREQUENT_ROTATION: 2,
    CryptoPolicyName.HYBRID_POST_QUANTUM_MODE: 3,
    CryptoPolicyName.QUANTUM_ESCALATED_MODE: 4,
    CryptoPolicyName.SESSION_QUARANTINE: 5,
}


def _max_policy(a: CryptoPolicyName, b: CryptoPolicyName) -> CryptoPolicyName:
    """Return whichever policy provides stronger protection."""
    return a if _POLICY_STRENGTH[a] >= _POLICY_STRENGTH[b] else b
