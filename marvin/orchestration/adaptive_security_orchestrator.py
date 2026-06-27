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

from ..advisors.council import SecurityCouncil
from ..audit.logger import AuditLogger
from ..consensus.final_decision_engine import FinalDecisionEngine, deliberate
from ..domain.enums import RiskLevel
from ..domain.models import (
    CouncilDecision,
    KeyRotationEvent,
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
    """Coordinate scoring, policy, keys, posture, and audit for one session.

    By default MARVIN uses its single, deterministic scoring + policy engines.
    When a :class:`SecurityCouncil` is supplied, each tick instead runs the
    governed multi-model pipeline (council advises → consensus → guardrails →
    final decision), while the deterministic engines remain the final authority.
    """

    def __init__(
        self,
        session_id: str,
        entropy_provider: QuantumEntropyProvider,
        scoring_engine: Optional[ThreatScoringEngine] = None,
        policy_engine: Optional[CryptoPolicyEngine] = None,
        key_manager: Optional[KeyRotationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        council: Optional[SecurityCouncil] = None,
        final_decision_engine: Optional[FinalDecisionEngine] = None,
    ) -> None:
        self.session_id = session_id
        self.entropy = entropy_provider
        self.scoring_engine = scoring_engine or ThreatScoringEngine()
        self.policy_engine = policy_engine or CryptoPolicyEngine()
        self.key_manager = key_manager or KeyRotationManager(session_id)
        self.audit = audit_logger or AuditLogger()
        self.council = council
        self.final_decision_engine = final_decision_engine or FinalDecisionEngine()

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

        # Entropy feeds key material + moving-target jitter in either mode.
        entropy = self.entropy.get_entropy()

        if self.council is not None:
            return self._council_tick(telemetry, entropy)
        return self._baseline_tick(telemetry, entropy)

    def _baseline_tick(self, telemetry, entropy) -> SecurityDecisionSnapshot:
        # Single-model deterministic path (Observe → Score → Select → Rotate).
        threat = self.scoring_engine.score(telemetry)
        policy = self.policy_engine.select(threat, telemetry)
        key_event = self.key_manager.evaluate(policy, entropy)

        explanation = self._build_explanation(threat, policy, key_event)
        next_action = self._next_action(
            policy.requires_quarantine or key_event.quarantined,
            policy.requires_reauthentication,
            key_event.rotated,
        )
        return self._finalize(
            telemetry=telemetry,
            risk_level=threat.risk_level,
            risk_score=threat.numeric_score,
            threat=threat,
            policy=policy,
            key_event=key_event,
            explanation=explanation,
            next_action=next_action,
        )

    def _council_tick(self, telemetry, entropy) -> SecurityDecisionSnapshot:
        # Governed multi-model path: council advises, MARVIN governs.
        baseline = self.scoring_engine.score(telemetry)
        deliberation = deliberate(
            telemetry,
            self.council,
            baseline_engine=self.scoring_engine,
            final_engine=self.final_decision_engine,
            baseline=baseline,
        )
        decision: CouncilDecision = deliberation.decision

        # Translate the governed decision into a concrete policy for the key
        # manager. The chosen policy *name* is authoritative; we then stamp the
        # governed action flags onto it.
        policy = self.policy_engine.decision_for(
            decision.final_policy, telemetry, rationale=[decision.explanation]
        )
        policy.requires_quarantine = decision.requires_quarantine
        policy.requires_reauthentication = decision.requires_reauthentication
        policy.requires_session_rekey = (
            policy.requires_session_rekey or decision.requires_key_rotation
        )

        key_event = self.key_manager.evaluate(
            policy, entropy, force_rekey=decision.requires_key_rotation
        )

        next_action = self._next_action(
            decision.requires_quarantine or key_event.quarantined,
            decision.requires_reauthentication,
            key_event.rotated,
            human_review=decision.human_review_required,
        )
        council_summary = self._council_summary(deliberation, decision)

        return self._finalize(
            telemetry=telemetry,
            risk_level=decision.final_risk_level,
            risk_score=baseline.numeric_score,
            threat=baseline,
            policy=policy,
            key_event=key_event,
            explanation=decision.explanation,
            next_action=next_action,
            council_summary=council_summary,
            council_full=deliberation.to_dict(),
        )

    def _finalize(
        self,
        *,
        telemetry,
        risk_level,
        risk_score,
        threat,
        policy,
        key_event,
        explanation,
        next_action,
        council_summary=None,
        council_full=None,
    ) -> SecurityDecisionSnapshot:
        quarantined = policy.requires_quarantine or key_event.quarantined
        active_key_id = (
            self.key_manager.active_key.key_id
            if self.key_manager.active_key is not None
            else None
        )
        self._posture = PostureState(
            risk_level=risk_level,
            active_policy=policy.policy_name,
            active_key_id=active_key_id,
            reauthentication_required=policy.requires_reauthentication,
            quarantined=quarantined,
            updated_at=utc_now(),
        )

        self.audit.record(
            session_id=self.session_id,
            tick_number=self._tick,
            telemetry=telemetry,
            threat=threat,
            policy=policy,
            key_event=key_event,
            posture=self._posture,
            explanation=explanation,
            council=council_full,
        )

        return SecurityDecisionSnapshot(
            session_id=self.session_id,
            tick_number=self._tick,
            telemetry_summary=telemetry.highlights(),
            risk_level=risk_level,
            risk_score=risk_score,
            selected_policy=policy.policy_name,
            key_event=key_event,
            posture_state=self._posture,
            explanation=explanation,
            next_action=next_action,
            council_summary=council_summary,
        )

    @staticmethod
    def _council_summary(deliberation, decision: CouncilDecision) -> dict:
        c = deliberation.consensus
        return {
            "risk_level_votes": c.risk_level_votes,
            "quarantine_votes": c.quarantine_votes,
            "available_advisors": c.available_advisors,
            "escalation_risk_level": c.escalation_risk_level.value,
            "majority_risk_level": c.majority_risk_level.value,
            "highest_confidence_advisor": c.highest_confidence_advisor,
            "has_disagreement": deliberation.disagreement.has_disagreement,
            "human_review_required": decision.human_review_required,
            "audit_severity": decision.audit_severity.value,
            "triggered_guardrails": deliberation.guardrails.triggered_rules,
            "advisors": [
                {
                    "name": r.advisor_name,
                    "risk_level": r.risk_level.value,
                    "recommended_policy": r.recommended_policy.value,
                    "requires_quarantine": r.requires_quarantine,
                    "confidence": r.confidence,
                }
                for r in deliberation.recommendations
            ],
        }

    def _frozen_snapshot(self, telemetry: TelemetrySnapshot) -> SecurityDecisionSnapshot:
        """Produce a snapshot for a session that is already quarantined."""
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
    def _next_action(
        quarantine: bool,
        reauth: bool,
        rotated: bool,
        human_review: bool = False,
    ) -> str:
        if quarantine:
            return "QUARANTINE_AND_INVESTIGATE"
        if human_review:
            return "ESCALATE_FOR_HUMAN_REVIEW"
        if reauth:
            return "REQUIRE_REAUTHENTICATION"
        if rotated:
            return "CONTINUE_MONITORING_WITH_NEW_KEY"
        return "CONTINUE_MONITORING"
