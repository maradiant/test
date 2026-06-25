"""AdaptiveSecurityOrchestrator — the brain of MARVIN.

This ties the whole lifecycle together for a single session:

    Observe → Score → Reason → Select Policy → Rotate Keys →
    Apply Posture → Log Decision → (repeat)

Each call to :meth:`tick` consumes one telemetry snapshot (and entropy),
produces a :class:`SecurityDecisionSnapshot`, updates the live posture, and
writes one audit event.
"""

from __future__ import annotations

from typing import Optional

from ..audit.logger import AuditLogger
from ..domain.enums import RiskLevel
from ..domain.models import (
    PostureState,
    SecurityDecisionSnapshot,
    TelemetrySnapshot,
    utc_now,
)
from ..entropy.provider import QuantumEntropyProvider
from ..keys.key_rotation_manager import KeyRotationManager
from ..policy.crypto_policy_engine import CryptoPolicyEngine
from ..scoring.threat_scoring_engine import ThreatScoringEngine


class AdaptiveSecurityOrchestrator:
    """Coordinate scoring, policy, keys, posture, and audit for one session."""

    def __init__(
        self,
        session_id: str,
        entropy_provider: QuantumEntropyProvider,
        scoring_engine: Optional[ThreatScoringEngine] = None,
        policy_engine: Optional[CryptoPolicyEngine] = None,
        key_manager: Optional[KeyRotationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.session_id = session_id
        self.entropy = entropy_provider
        self.scoring_engine = scoring_engine or ThreatScoringEngine()
        self.policy_engine = policy_engine or CryptoPolicyEngine()
        self.key_manager = key_manager or KeyRotationManager(session_id)
        self.audit = audit_logger or AuditLogger()

        self._tick = 0
        self._posture = PostureState(
            risk_level=RiskLevel.LOW,
            active_policy=None,  # type: ignore[arg-type]
            active_key_id=None,
            reauthentication_required=False,
            quarantined=False,
            updated_at=utc_now(),
        )

    @property
    def posture(self) -> PostureState:
        return self._posture

    @property
    def tick_number(self) -> int:
        return self._tick

    def tick(self, telemetry: TelemetrySnapshot) -> SecurityDecisionSnapshot:
        """Run one full decision cycle over a telemetry snapshot."""
        self._tick += 1

        # If the session is already quarantined, hold it there.
        if self._posture.quarantined:
            return self._frozen_snapshot(telemetry)

        # 1. Entropy (feeds key material + moving-target jitter).
        entropy = self.entropy.get_entropy()

        # 2. Score risk (explainable).
        threat = self.scoring_engine.score(telemetry)

        # 3. Reason + select crypto policy.
        policy = self.policy_engine.select(threat, telemetry)

        # 4. Decide on key rotation / quarantine.
        key_event = self.key_manager.evaluate(policy, entropy)

        # 5. Apply / update posture.
        quarantined = policy.requires_quarantine or key_event.quarantined
        active_key_id = (
            self.key_manager.active_key.key_id
            if self.key_manager.active_key is not None
            else None
        )
        self._posture = PostureState(
            risk_level=threat.risk_level,
            active_policy=policy.policy_name,
            active_key_id=active_key_id,
            reauthentication_required=policy.requires_reauthentication,
            quarantined=quarantined,
            updated_at=utc_now(),
        )

        explanation = self._build_explanation(threat, policy, key_event)
        next_action = self._next_action(threat, policy, key_event)

        # 6. Log decision (audit trail).
        self.audit.record(
            session_id=self.session_id,
            tick_number=self._tick,
            telemetry=telemetry,
            threat=threat,
            policy=policy,
            key_event=key_event,
            posture=self._posture,
            explanation=explanation,
        )

        return SecurityDecisionSnapshot(
            session_id=self.session_id,
            tick_number=self._tick,
            telemetry_summary=telemetry.highlights(),
            risk_level=threat.risk_level,
            risk_score=threat.numeric_score,
            selected_policy=policy.policy_name,
            key_event=key_event,
            posture_state=self._posture,
            explanation=explanation,
            next_action=next_action,
        )

    def _frozen_snapshot(self, telemetry: TelemetrySnapshot) -> SecurityDecisionSnapshot:
        """Produce a snapshot for a session that is already quarantined."""
        from ..domain.models import KeyRotationEvent

        key_event = KeyRotationEvent(
            rotated=False,
            reason="Session quarantined; no key activity.",
            quarantined=True,
        )
        explanation = (
            "Session remains quarantined from a prior CRITICAL decision. "
            "Manual investigation / re-onboarding is required to resume."
        )
        threat = self.scoring_engine.score(telemetry)
        policy = self.policy_engine.select(threat, telemetry)
        self.audit.record(
            session_id=self.session_id,
            tick_number=self._tick,
            telemetry=telemetry,
            threat=threat,
            policy=policy,
            key_event=key_event,
            posture=self._posture,
            explanation=explanation,
        )
        return SecurityDecisionSnapshot(
            session_id=self.session_id,
            tick_number=self._tick,
            telemetry_summary=telemetry.highlights(),
            risk_level=self._posture.risk_level,
            risk_score=1.0,
            selected_policy=self._posture.active_policy,
            key_event=key_event,
            posture_state=self._posture,
            explanation=explanation,
            next_action="HOLD_QUARANTINE",
        )

    @staticmethod
    def _build_explanation(threat, policy, key_event) -> str:
        reasons = "; ".join(threat.reasons)
        rationale = "; ".join(policy.rationale)
        key_note = key_event.reason
        return (
            f"Risk {threat.risk_level.value} (score {threat.numeric_score:.2f}, "
            f"confidence {threat.confidence:.2f}). Why: {reasons}. "
            f"Policy {policy.policy_name.value} — {rationale}. "
            f"Keys: {key_note}"
        )

    @staticmethod
    def _next_action(threat, policy, key_event) -> str:
        if policy.requires_quarantine or key_event.quarantined:
            return "QUARANTINE_AND_INVESTIGATE"
        if policy.requires_reauthentication:
            return "REQUIRE_REAUTHENTICATION"
        if key_event.rotated:
            return "CONTINUE_MONITORING_WITH_NEW_KEY"
        return "CONTINUE_MONITORING"
