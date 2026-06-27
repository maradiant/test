"""PolicyGuardrails — the deterministic hard rules that bind the council.

This is the heart of "LLMs advise; MARVIN governs." No model opinion can move
the system below these floors, and certain conditions forbid inaction outright.
The guardrails are evaluated purely from telemetry (never from model output), so
they are transparent, testable, and immune to model error or manipulation.
"""

from __future__ import annotations

from ..domain.enums import DataSensitivity, RiskLevel
from ..domain.models import GuardrailVerdict, TelemetrySnapshot

_SENSITIVE = {DataSensitivity.RESTRICTED, DataSensitivity.MISSION_CRITICAL}


class PolicyGuardrails:
    """Evaluate hard security rules against a telemetry snapshot."""

    def evaluate(self, telemetry: TelemetrySnapshot) -> GuardrailVerdict:
        min_risk = RiskLevel.LOW
        mandatory_quarantine = False
        quarantine_eligible = False
        forbid_no_action = False
        require_key_rotation = False
        require_reauth = False
        rules: list[str] = []

        t = telemetry
        sensitive = t.data_sensitivity in _SENSITIVE

        # R1: Interception on sensitive data — inaction is forbidden and
        # quarantine becomes eligible. (The user's canonical rule.)
        if t.suspected_interception and sensitive:
            forbid_no_action = True
            quarantine_eligible = True
            require_key_rotation = True
            require_reauth = True
            min_risk = RiskLevel.max(min_risk, RiskLevel.HIGH)
            rules.append("INTERCEPTION_ON_SENSITIVE_DATA")

        # R2: Suspected interception (any data) — floor at HIGH, rotate, no inaction.
        elif t.suspected_interception:
            forbid_no_action = True
            require_key_rotation = True
            min_risk = RiskLevel.max(min_risk, RiskLevel.HIGH)
            rules.append("SUSPECTED_INTERCEPTION")

        # R3: Authentication burst — force reauthentication, floor at MEDIUM.
        if t.failed_auth_attempts >= 10:
            forbid_no_action = True
            require_reauth = True
            min_risk = RiskLevel.max(min_risk, RiskLevel.MEDIUM)
            rules.append("AUTH_BURST")

        # R4: Collapsed trust under heavy pressure — mandatory quarantine.
        if t.endpoint_trust_score <= 0.2 and t.adversary_pressure >= 0.8:
            mandatory_quarantine = True
            quarantine_eligible = True
            forbid_no_action = True
            min_risk = RiskLevel.max(min_risk, RiskLevel.CRITICAL)
            rules.append("COLLAPSED_TRUST_UNDER_PRESSURE")

        # R5: Mission-critical data always rotates keys and floors at MEDIUM.
        if t.data_sensitivity is DataSensitivity.MISSION_CRITICAL:
            require_key_rotation = True
            min_risk = RiskLevel.max(min_risk, RiskLevel.MEDIUM)
            rules.append("MISSION_CRITICAL_DATA")

        # R6: Repeated prior incidents on the session — floor at HIGH.
        if t.previous_incident_count >= 5:
            min_risk = RiskLevel.max(min_risk, RiskLevel.HIGH)
            rules.append("REPEAT_INCIDENT_HISTORY")

        return GuardrailVerdict(
            min_risk_level=min_risk,
            mandatory_quarantine=mandatory_quarantine,
            quarantine_eligible=quarantine_eligible,
            forbid_no_action=forbid_no_action,
            require_key_rotation=require_key_rotation,
            require_reauthentication=require_reauth,
            triggered_rules=rules,
        )
